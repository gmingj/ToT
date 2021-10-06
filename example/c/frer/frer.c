#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>

#include <pcap/pcap.h>
#include <linux/if_ether.h>

#define SLIST_HEAD(name, type)						\
struct name {								\
	struct type *slh_first;	/* first element */			\
}
 
#define	SLIST_HEAD_INITIALIZER(head)					\
	{ NULL }
 
#define SLIST_ENTRY(type)						\
struct {								\
	struct type *sle_next;	/* next element */			\
}
 
/*
 * Singly-linked List access methods.
 */
#define	SLIST_FIRST(head)	((head)->slh_first)
#define	SLIST_END(head)		NULL
#define	SLIST_EMPTY(head)	(SLIST_FIRST(head) == SLIST_END(head))
#define	SLIST_NEXT(elm, field)	((elm)->field.sle_next)

#define	SLIST_FOREACH(var, head, field)					\
	for((var) = SLIST_FIRST(head);					\
	    (var) != SLIST_END(head);					\
	    (var) = SLIST_NEXT(var, field))

#define	SLIST_FOREACH_PREVPTR(var, varp, head, field)			\
	for ((varp) = &SLIST_FIRST((head));				\
	    ((var) = *(varp)) != SLIST_END(head);			\
	    (varp) = &SLIST_NEXT((var), field))

/*
 * Singly-linked List functions.
 */
#define	SLIST_INIT(head) {						\
	SLIST_FIRST(head) = SLIST_END(head);				\
}

#define	SLIST_INSERT_AFTER(slistelm, elm, field) do {			\
	(elm)->field.sle_next = (slistelm)->field.sle_next;		\
	(slistelm)->field.sle_next = (elm);				\
} while (0)

#define	SLIST_INSERT_HEAD(head, elm, field) do {			\
	(elm)->field.sle_next = (head)->slh_first;			\
	(head)->slh_first = (elm);					\
} while (0)

#define	SLIST_REMOVE_NEXT(head, elm, field) do {			\
	(elm)->field.sle_next = (elm)->field.sle_next->field.sle_next;	\
} while (0)

#define	SLIST_REMOVE_HEAD(head, field) do {				\
	(head)->slh_first = (head)->slh_first->field.sle_next;		\
} while (0)

#define SLIST_REMOVE(head, elm, type, field) do {			\
	if ((head)->slh_first == (elm)) {				\
		SLIST_REMOVE_HEAD((head), field);			\
	} else {							\
		struct type *curelm = (head)->slh_first;		\
									\
		while (curelm->field.sle_next != (elm))			\
			curelm = curelm->field.sle_next;		\
		curelm->field.sle_next =				\
		    curelm->field.sle_next->field.sle_next;		\
		_Q_INVALIDATE((elm)->field.sle_next);			\
	}								\
} while (0)

#define TIMEOUT 100 /* ms */
#define FRER_HLEN 20
#define ETH_P_8021CB 0xF1C1

#define BITMAP_SET(POS) (bitmap[POS/8] |= 1 << (POS%8))
#define BITMAP_RESET(POS) (bitmap[POS/8] &= ~(1 << (POS%8)))
#define BITMAP_TEST(POS) ((bitmap[POS/8] >> (POS%8) & 0x01) == 1)

#define SHORTOPTS "hdi:o:f:m:tl"

struct rtag_st {
    unsigned short rsvd;
    unsigned short seq;
    unsigned short type;
};

struct dev_out_st {
    SLIST_ENTRY(dev_out_st) le;
    unsigned char dest[ETH_ALEN];
    unsigned char source[ETH_ALEN];
    char *dev;
    pcap_t *pcap_hdl;
    int cnt;
};

struct dev_in_st {
    SLIST_ENTRY(dev_in_st) le;
    char *dev;
    pcap_t *pcap_hdl;
    int cnt;
};

typedef struct {
    char role;
    int debug;
    char *bpf;
    int promisc;
    SLIST_HEAD(header_in_st, dev_in_st) devilh;
    SLIST_HEAD(header_out_st, dev_out_st) devolh;
    pcap_handler callback;
} ctx_t;

static ctx_t *ctx;
static int sig_exit;
static unsigned short sequence_number;
static unsigned char bitmap[64*1024/8];
static unsigned short window_pos = 0;

#define SHORTOPTS "hdi:o:f:m:tl"
static const struct option longopts[] = {
    { "help", no_argument, NULL, 'h' },
    { "debug", no_argument, NULL, 'd' },
    { "in-interface", required_argument, NULL, 'i' },
    { "out-interface", required_argument, NULL, 'o' },
    { "packet-filter", required_argument, NULL, 'f' },
	{ "promisc", required_argument, NULL, 'm' },
	{ "frer-talker", no_argument, NULL, 't' },
	{ "frer-listener", no_argument, NULL, 'l' },
	{ 0, 0, 0, 0 },
};

static int get_mac_address(char *dev, unsigned char *dest, unsigned char *source)
{
    unsigned char dmac1[ETH_ALEN] = {0x00,0x0c,0x29,0x9b,0x35,0x0d};
    unsigned char dmac2[ETH_ALEN] = {0x00,0x0c,0x29,0x9b,0x35,0x17};
    unsigned char smac[ETH_ALEN] = {0x09, 0x08, 0x07, 0x06, 0x05, 0x04};

    if (strcmp(dev, "eth1") == 0)
        memcpy(dest, dmac1, ETH_ALEN);
    if (strcmp(dev, "eth2") == 0)
        memcpy(dest, dmac2, ETH_ALEN);
    memcpy(source, smac, ETH_ALEN);

    return 0;
}

static char *hexdump(const unsigned char *buffer, int len)
{
    int i = 0, j = 0;
    static char str[BUFSIZ];

    if (len > BUFSIZ/3)
        return "";

    memset(str, '\0', BUFSIZ);
    for (; i < len; i++) {
        sprintf(&str[j], " %02X", buffer[i]);
        j += 3;
    }
    sprintf(&str[j], " ");

    return str;
}

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
    struct dev_in_st *elmi;                                                          

    SLIST_FOREACH(elmi, &ctx->devilh, le) {
        if (elmi->pcap_hdl)
            pcap_breakloop(elmi->pcap_hdl);
    }

    sig_exit = 1;
}

void frer_uninit(ctx_t *ctx)
{
    struct dev_in_st *elmi;                                                          
    struct dev_out_st *elmo;                                                          
                                                                                 
    if (!ctx)
        return;

    SLIST_FOREACH(elmi, &ctx->devilh, le) {
        if (elmi->pcap_hdl) {
            pcap_close(elmi->pcap_hdl);
            elmi->pcap_hdl = NULL;
        }
    }

    SLIST_FOREACH(elmo, &ctx->devolh, le) {
        if (elmo->pcap_hdl) {
            pcap_close(elmo->pcap_hdl);
            elmo->pcap_hdl = NULL;
        }
    }
}

int frer_init(ctx_t *ctx)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask;
    struct bpf_program bp;
    struct dev_in_st *elmi;                                                          
    struct dev_out_st *elmo;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGHUP, sig_handler);

    SLIST_FOREACH(elmi, &ctx->devilh, le) {
        elmi->pcap_hdl = pcap_open_live(elmi->dev, BUFSIZ, ctx->promisc, TIMEOUT, errbuf);
        if (!elmi->pcap_hdl) {
            fprintf(stderr, "%s\n", errbuf);
            goto error;
        }

        if (pcap_setdirection(elmi->pcap_hdl, PCAP_D_IN) != 0) {
            pcap_perror(elmi->pcap_hdl, NULL);
            goto error;
        }

        if (!ctx->bpf)
            continue;

        if (pcap_lookupnet(elmi->dev, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "%s\n", errbuf);
            goto error;
        }

        if (pcap_compile(elmi->pcap_hdl, &bp, ctx->bpf, 0, mask) == -1) {
            pcap_perror(elmi->pcap_hdl, NULL);
            goto error;
        }

        if (pcap_setfilter(elmi->pcap_hdl, &bp) == -1) {
            pcap_perror(elmi->pcap_hdl, NULL);
            goto error;
        }
    }

    SLIST_FOREACH(elmo, &ctx->devolh, le) {
        elmo->pcap_hdl = pcap_open_live(elmo->dev, BUFSIZ, 0, TIMEOUT, errbuf);
        if (!elmo->pcap_hdl) {
            fprintf(stderr, "%s\n", errbuf);
            goto error;
        }

        if (get_mac_address(elmo->dev, elmo->dest, elmo->source) != 0) {
            fprintf(stderr, "error: <if-%s> get mac\n", elmo->dev);
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
    
    if (len + FRER_HLEN > BUFSIZ)
        return 0;

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

    if (ctx->debug) {
        fprintf(stdout, "Captured: len(%d) %s\n\n", h->len, hexdump(bytes, 46));
    }

    SLIST_FOREACH(elm, &ctx->devolh, le) {
        buflen = frer_encap(elm, bytes, h->len, buf);
        if (buflen == 0)
            return;

        if (ctx->debug) {
            fprintf(stdout, "Sent: len(%d) %s\n\n", buflen, hexdump(buf, 46));
        }

        if (pcap_sendpacket(elm->pcap_hdl, buf, buflen) != 0) {
            pcap_perror(elm->pcap_hdl, NULL);
            continue;
        }
        elm->cnt += 1;
    }

    sequence_number++;
}

static void frer_listener(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    ctx_t *ctx = (ctx_t *)user;
    struct dev_out_st *elm;                                                          
    unsigned char buf[BUFSIZ];
    int buflen;

    if (ctx->debug) {
        fprintf(stdout, "Captured: len(%d) %s\n\n", h->len, hexdump(bytes, 46));
    }

    //ctx->devi.cnt += 1;

    SLIST_FOREACH(elm, &ctx->devolh, le) {
        buflen = frer_decap(elm, bytes, h->len, buf);
        if (buflen == 0)
            return;

        if (ctx->debug) {
            fprintf(stdout, "Sent: len(%d) %s\n\n", buflen, hexdump(buf, 46));
        }

        if (pcap_sendpacket(elm->pcap_hdl, buf, buflen) != 0) {
            pcap_perror(elm->pcap_hdl, NULL);
            continue;
        }
        elm->cnt += 1;
    }
}

void run(ctx_t *ctx)
{
    struct dev_in_st *elmi;                                                          
    struct dev_out_st *elmo;                                                          
    struct pcap_pkthdr hdr;
    const u_char *data;

    if (frer_init(ctx) != 0)
        return;

    while (!sig_exit) {
        SLIST_FOREACH(elmi, &ctx->devilh, le) {
            if (sig_exit)
                break;

            data = pcap_next(elmi->pcap_hdl, &hdr);
            if (!data) {
                continue;
            }
            else {
                elmi->cnt += 1;
                ctx->callback((u_char *)ctx, &hdr, data);
            }
        }
    }

    fprintf(stdout, "\n");
    SLIST_FOREACH(elmi, &ctx->devilh, le) {
        fprintf(stdout, "%s in %d packets captured\n", elmi->dev, elmi->cnt);
    }
    SLIST_FOREACH(elmo, &ctx->devolh, le) {
        fprintf(stdout, "%s out %d packets sent\n", elmo->dev, elmo->cnt);
    }

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
    fprintf(stderr, "version 0.1.0, %s %s\n", __DATE__, __TIME__);
    fprintf(stderr, "Usage: %s [-t] [-l] [-i <device>] [-o <device>]\n"
                    "              [-h] [-m] [-d] [-f <expression>] \n\n", bin);
    fprintf(stderr, "Examples: %s -t -i eth0 -o eth1 eth2 -f 'udp dst port 5201'\n", bin);
    fprintf(stderr, "          %s -l -i eth1 eth2 -o eth3 -f 'ether[12:2]=0xf1c1'\n", bin);
}

static int parse_arguments(ctx_t *ctx, int argc, char **argv)
{
    int op, i;

    while ((op = getopt_long(argc, argv, SHORTOPTS, longopts, NULL)) != -1) {
        switch (op) {
            case 't':
            case 'l':
                ctx->role = op;
                break;
            case 'f':
                ctx->bpf = strdup(optarg);
                break;
            case 'm':
                ctx->promisc = 1;
                break;
            case 'd':
                ctx->debug = 1;
                break;
            case 'i': {
                for (i = optind - 1; i < argc && argv[i][0] != '-'; i++) {
                    struct dev_in_st *elmi = (struct dev_in_st *)malloc(sizeof(struct dev_in_st));
                    if (!elmi) {
                        fprintf(stderr, "error: malloc\n");
                        exit(1);
                    }

                    elmi->dev = strdup(argv[i]);
                    SLIST_INSERT_HEAD(&ctx->devilh, elmi, le);
                }
                break;
            }
            case 'e': {
                for (i = optind - 1; i < argc && argv[i][0] != '-'; i++) {
                    struct dev_out_st *elmo = (struct dev_out_st *)malloc(sizeof(struct dev_out_st));
                    if (!elmo) {
                        fprintf(stderr, "error: malloc\n");
                        exit(1);
                    }

                    elmo->dev = strdup(argv[i]);
                    SLIST_INSERT_HEAD(&ctx->devolh, elmo, le);
                }
                break;
            }
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

