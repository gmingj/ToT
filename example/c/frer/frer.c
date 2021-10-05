#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>

#include <pcap/pcap.h>
#include <linux/if_ether.h>

#include "list.h"
#include "get_mac.h"

#define TIMEOUT 512
#define FRER_HLEN 20
#define ETH_P_8021CB 0xF1C1

#define BITMAP_SET(POS) (bitmap[POS/8] |= 1 << (POS%8))
#define BITMAP_RESET(POS) (bitmap[POS/8] &= ~(1 << (POS%8)))
#define BITMAP_TEST(POS) ((bitmap[POS/8] >> (POS%8) & 0x01) == 1)

#define SHORTOPTS "hdi:e:f:tl"

struct rtag_st {
    unsigned short rsvd;
    unsigned short seq;
    unsigned short type;
};

struct dev_attr_st {
    char *dev;
    pcap_t *pcap_hdl;
    int cnt;
};

struct dev_out_st {
    SLIST_ENTRY(dev_out_st) le;

    struct dev_attr_st devatt;
    unsigned char dest[ETH_ALEN];
    unsigned char source[ETH_ALEN];
};

struct dev_in_st {
    char *bpf;
    int promisc;
    struct dev_attr_st devatt;
};

typedef struct {
    char role;
    struct dev_in_st devi;
    SLIST_HEAD(head_st, dev_out_st) devolh;
    pcap_handler callback;
} ctx_t;

static ctx_t *ctx;
static unsigned short sequence_number;
static unsigned char bitmap[64*1024/8];
static unsigned short window_pos = 0;

static const struct option longopts[] = {
    { "help", no_argument, NULL, 'h' },
    { "debug", no_argument, NULL, 'd' },
    { "ingress-interface", required_argument, NULL, 'i' },
    { "egress-interface", required_argument, NULL, 'e' },
    { "packet-filter", required_argument, NULL, 'f' },
	{ "frer-talker", no_argument, NULL, 't' },
	{ "frer-listener", no_argument, NULL, 'l' },
	{ 0, 0, 0, 0 },
};

/* Whenever the sequence increases by 16k, clear the first 8k */
static void frer_recover_sequence(unsigned short pos)
{
#define RCVSZ 8*1024
#define WNDSZ 16*1024

    unsigned int current_pos = pos < window_pos ? pos + 64*1024 : pos;

    if ((current_pos - window_pos) > WNDSZ) {
        memset(&bitmap[window_pos/8], 0, RCVSZ/8);
        window_pos += RCVSZ;
    }
}

void sig_handler(int sig)
{
    if (ctx->devi.devatt.pcap_hdl)
        pcap_breakloop(ctx->devi.devatt.pcap_hdl);
}

int frer_create_pcap_in(ctx_t *ctx)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask;
    struct bpf_program bp;
    pcap_t *pcap_hdl;

    pcap_hdl = pcap_open_live(ctx->devi.devatt.dev, BUFSIZ, ctx->devi.promisc, TIMEOUT, errbuf);
    if (!pcap_hdl) {
        fprintf(stderr, "%s\n", errbuf);
        goto error;
    }
    ctx->devi.devatt.pcap_hdl = pcap_hdl;

    if (pcap_setdirection(pcap_hdl, PCAP_D_IN) != 0) {
        pcap_perror(pcap_hdl, NULL);
        goto error;
    }

    if (!ctx->devi.bpf)
        return 0;

    if (pcap_lookupnet(ctx->devi.devatt.dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "%s\n", errbuf);
        goto error;
    }

    if (pcap_compile(pcap_hdl, &bp, ctx->devi.bpf, 0, mask) == -1) {
        pcap_perror(pcap_hdl, NULL);
        goto error;
    }

    if (pcap_setfilter(pcap_hdl, &bp) == -1) {
        pcap_perror(pcap_hdl, NULL);
        goto error;
    }

    return 0;

error:
    if (pcap_hdl)
        pcap_close(pcap_hdl);

    ctx->devi.devatt.pcap_hdl = NULL;
    return -1;
}

void frer_uninit(ctx_t *ctx)
{
    struct dev_out_st *elm;                                                          
                                                                                 
    if (!ctx)
        return;

    if (ctx->devi.devatt.pcap_hdl)
        pcap_close(ctx->devi.devatt.pcap_hdl);

    SLIST_FOREACH(elm, &ctx->devolh, le) {
        if (elm->devatt.pcap_hdl)
            pcap_close(elm->devatt.pcap_hdl);
    }
}

int frer_init(ctx_t *ctx)
{
    struct dev_out_st *elm;
    char errbuf[PCAP_ERRBUF_SIZE];

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    //signal(SIGHUP, sig_handler);

    if (frer_create_pcap_in(ctx) != -1)
        goto error;

    SLIST_FOREACH(elm, &ctx->devolh, le) {
        elm->devatt.pcap_hdl = pcap_open_live(elm->devatt.dev, BUFSIZ, 0, TIMEOUT, errbuf);
        if (!elm->devatt.pcap_hdl) {
            fprintf(stderr, "%s\n", errbuf);
            goto error;
        }

        if (get_mac_address(elm->devatt.dev, elm->dest, elm->source) != 0) {
            fprintf(stderr, "error: <if-%s> get mac\n", elm->devatt.dev);
            goto error;
        }
    }

    return 0;

error:
    frer_uninit(ctx);
    return -1;
}

static int frer_encap(struct dev_out_st *elm, const void *data, int len, unsigned char *buf)
{
    struct rtag_st rtag = {0, htons(sequence_number), 0};
    struct ethhdr eh;
    
    memcpy(eh.h_dest, elm->dest, ETH_ALEN);
    memcpy(eh.h_source, elm->source, ETH_ALEN);
    eh.h_proto = htons(ETH_P_8021CB);
    memcpy(buf, &eh, ETH_HLEN);

    memcpy(buf + ETH_HLEN, &rtag, sizeof(struct rtag_st));

    memcpy(buf + FRER_HLEN, data, len);

    return FRER_HLEN + len;
}

static int frer_decap(struct dev_out_st *elm, const void *data, int len, unsigned char *buf)
{
    int hlen, seqofs;
    struct ethhdr *eh;
    const unsigned char *bytes = (const unsigned char *)data;

    //TODO: fileter dlt, set bpf
    eh = (struct ethhdr *)bytes;
    if (eh->h_proto == htons(ETH_P_8021Q)) {
        if (*((unsigned short *)&bytes[ETH_HLEN + 2]) != htons(ETH_P_8021CB))
            return 0;

        hlen = FRER_HLEN + 4;
        seqofs = ETH_HLEN + 6;
    }
    else if (eh->h_proto == htons(ETH_P_8021CB)) {
        hlen = FRER_HLEN;
        seqofs = ETH_HLEN + 2;
    }
    else
        return 0;

    unsigned short seq = ntohs(*((unsigned short *)&bytes[seqofs]));
    if (BITMAP_TEST(seq))
        return 0;
    
    BITMAP_SET(seq);
    frer_recover_sequence(seq);

    memcpy(buf, bytes + hlen, len - hlen);
    return len - hlen;
}

static void frer_talker(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    ctx_t *ctx = (ctx_t *)user;
    struct dev_out_st *elm;                                                          
    unsigned char buf[BUFSIZ];
    int buflen;

#ifdef DEBUG
    fprintf(stdout, "Recvd pkt: len(%d) %s\n\n", h->len, hexdump(bytes, 46));
    fflush(stdout);
#endif

    ctx->devi.devatt.cnt += 1;
    
    SLIST_FOREACH(elm, &ctx->devolh, le) {
        buflen = frer_encap(elm, bytes, h->len, buf);
        if (pcap_sendpacket(elm->devatt.pcap_hdl, buf, buflen) != 0) {
            pcap_perror(elm->devatt.pcap_hdl, NULL);
            continue;
        }
        elm->devatt.cnt += 1;
    }

    sequence_number++;
}

static void frer_listener(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    ctx_t *ctx = (ctx_t *)user;
    struct dev_out_st *elm;                                                          
    unsigned char buf[BUFSIZ];
    int buflen;

#ifdef DEBUG
    fprintf(stdout, "Recvd pkt: len(%d) %s\n\n", h->len, hexdump(bytes, 46));
    fflush(stdout);
#endif

    ctx->devi.devatt.cnt += 1;

    SLIST_FOREACH(elm, &ctx->devolh, le) {
        buflen = frer_decap(elm, bytes, h->len, buf);
        if (buflen == 0)
            continue;

        if (pcap_sendpacket(elm->devatt.pcap_hdl, buf, buflen) != 0) {
            pcap_perror(elm->devatt.pcap_hdl, NULL);
            continue;
        }
        elm->devatt.cnt += 1;
    }
}

void run(ctx_t *ctx)
{
    struct dev_out_st *elm;                                                          

    if (frer_init(ctx) != 0)
        goto error;

    if (pcap_loop(ctx->devi.devatt.pcap_hdl, -1, ctx->callback, (u_char *)ctx) == -1) {
        pcap_perror(ctx->devi.devatt.pcap_hdl, NULL);
        goto error;
    }

    fprintf(stdout, "\n");
    fprintf(stdout, "%s ingress %d packets captured\n", ctx->devi.devatt.dev, ctx->devi.devatt.cnt);
    SLIST_FOREACH(elm, &ctx->devolh, le) {
        fprintf(stdout, "%s egress %d packets sent\n", elm->devatt.dev, elm->devatt.cnt);
    }

error:
    frer_uninit(ctx);
}

static ctx_t *new_ctx(void)
{
    ctx_t *ctx = malloc(sizeof(ctx_t));
    if (!ctx)
        return NULL;

    memset(ctx, 0, sizeof(ctx_t));
    return ctx;
}

static void usage(const char *bin)
{
    fprintf(stderr, "version 0.0.1, %s %s\n", __DATE__, __TIME__);
    fprintf(stderr, "\n");
    fprintf(stderr, "Usage: %s [-h] [-i <ingress device>] [-e <egress device>] [-f 'udp']\n", bin);
    fprintf(stderr, "e.g.   %s -t -i eth2 -e eth0 eth1 -f 'udp dst port 5201'", bin);
    fprintf(stderr, "       %s -l -e eth2", bin);
}

static int parse_arguments(ctx_t *ctx, int argc, char **argv)
{
    int op;

    while ((op = getopt_long(argc, argv, SHORTOPTS, longopts, NULL)) != -1) {
        switch (op) {
            case 't':
            case 'l':
                ctx->role = op;
                break;
            case 'i':
                ctx->devi.devatt.dev = strdup(optarg);
                break;
            case 'e': {
                struct dev_out_st *elm = (struct dev_out_st *)malloc(sizeof(struct dev_out_st));
                if (!elm) {
                    fprintf(stderr, "error: malloc\n");
                    exit(1);
                }

                for (int i = optind - 1; i < argc && argv[i][0] != '-'; i++) {
                    elm->devatt.dev = strdup(argv[i]);
                    SLIST_INSERT_HEAD(&ctx->devolh, elm, le);
                }
                break;
            }
            case 'f':
                ctx->devi.bpf = strdup(optarg);
                break;
            case 'h':
            default:
                return -1;
        }
    }

    return 0;
}

int main(int argc, char *argv[])
{
    ctx = new_ctx();
    if (!ctx) {
        fprintf(stderr, "error: new ctx\n");
        return -1;
    }

    if (parse_arguments(ctx, argc, argv) < 0) {
        usage(argv[0]);
        exit(1);
    }

    if (ctx->role == 't') {
        ctx->callback = frer_talker;
    }
    else if (ctx->role == 'l') {
        ctx->callback = frer_listener;
    }
    else {
        usage(argv[0]);
        exit(1);
    }

    run(ctx);
    return 0;
}

