#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>

#include <pcap/pcap.h>

#include "list.h"

#define HAVE_FRER

#if defined(HAVE_FRER)
#define R_FLAG "Rtl"
#else
#define R_FLAG
#endif

#define SHORTOPTS "hdi:e:f:" R_FLAG
#define TIMEOUT 512

enum {
    IENONE,                 // No error
    IENEWCXT,               // Unable to malloc
    IEPCAPOPEN,             // Unable to create pcap handle
};

struct elm_st {
    SLIST_ENTRY(elm_st) le;
    char *edev;
    pcap_t *e_pcap_hdl;
    int ecnt;
};

typedef struct {
    char *idev;
    int ipromisc;
    pcap_t *i_pcap_hdl;
    char *bpf;
    int icnt;

    SLIST_HEAD(edev_hdr_t, elm_st) edev_hdr;
    pcap_handler callback;
} ctx_t;

int ierrno;
ctx_t *ctx;

static const struct option longopts[] = {
    { "help", no_argument, NULL, 'h' },
    { "debug", no_argument, NULL, 'd' },
    { "ingress-interface", required_argument, NULL, 'i' },
    { "egress-interface", required_argument, NULL, 'e' },
    { "packet-filter", required_argument, NULL, 'f' },

#if defined(HAVE_FRER)
	{ "frer-talker", no_argument, NULL, 't' },
	{ "frer-listener", no_argument, NULL, 'l' },
#endif
	{ 0, 0, 0, 0 },
};

static void passthrough(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    ctx_t *ctx = (ctx_t *)user;
    struct elm_st *elm;

#if 0
    struct timeval tvbuf;
    tvbuf.tv_sec = h->ts.tv_sec;
    tvbuf.tv_usec = h->ts.tv_usec;
#endif

#ifdef DEBUG
    fprintf(stdout, "Recvd pkt: len(%d) %s\n\n", h->len, hexdump(bytes, 46));
    //fflush(stdout);
#endif

    ctx->icnt += 1;

    SLIST_FOREACH(elm, &ctx->edev_hdr, le) {
        if (pcap_sendpacket(elm->e_pcap_hdl, bytes, h->len) != 0) {
            pcap_perror(elm->e_pcap_hdl, NULL);
            return;
        }
        elm->ecnt += 1;
    }

}

const char *istrerror(int errno)
{
    static char str[1024];
    sprintf(str, "errno(%d) - NA", errno);
    return str;
}

void errexit(ctx_t *ctx, const char *format, ...)
{
    va_list ap;
    char str[1024];

#if 0
    if (ctx != NULL && ctx->timestamps) {
        time(&now);
        ltm = localtime(&now);
        strftime(iperf_timestrerr, sizeof(iperf_timestrerr), "%c ", ltm);
        ct = iperf_timestrerr;
    }
#endif

    va_start(ap, format);
    vsnprintf(str, sizeof(str), format, ap);

    fprintf(stderr, "%s\n", str);
    if (ctx) {
    }

    exit(1);
}

static void set_defaults(ctx_t *ctx)
{
    ctx->idev = "any";
    ctx->ipromisc = 1;
    ctx->callback = passthrough;
}

static ctx_t *new_ctx(void)
{
    ctx_t *ctx = malloc(sizeof(ctx_t));
    if (!ctx) {
        ierrno = IENEWCXT;
        return NULL;
    }

    return ctx;
}

char *hexdump(const unsigned char *buffer, int len)
{
    int i = 0, j = 0;
    static char str[4096];

    memset(str, '\0', 4096);
    for (; i < len; i++) {
        sprintf(&str[j], " %02X", buffer[i]);
        j += 3;
    }
    sprintf(&str[j], " ");

    return str;
}

void sig_handler(int sig)
{
    pcap_breakloop(ctx->i_pcap_hdl);
}

static int init_egress(ctx_t *ctx)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct elm_st *elm;

    SLIST_FOREACH(elm, &ctx->edev_hdr, le) {
        elm->e_pcap_hdl = pcap_open_live(elm->edev, BUFSIZ, 1, TIMEOUT, errbuf);
        if (!elm->e_pcap_hdl) {
            fprintf(stderr, "%s\n", errbuf);
            return -1;
        }
    }

    return 0;
}

static int init_ingress(ctx_t *ctx)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask;
    struct bpf_program bpf;

    ctx->i_pcap_hdl = pcap_open_live(ctx->idev, BUFSIZ, ctx->ipromisc, TIMEOUT, errbuf);
    if (!ctx->i_pcap_hdl) {
        fprintf(stderr, "%s\n", errbuf);
        return -1;
    }

    if (pcap_lookupnet(ctx->idev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "%s\n", errbuf);
        return -1;
    }

    if (pcap_compile(ctx->i_pcap_hdl, &bpf, ctx->bpf, 0, mask) == -1) {
        pcap_perror(ctx->i_pcap_hdl, NULL);
        return -1;
    }

    if (pcap_setfilter(ctx->i_pcap_hdl, &bpf) == -1) {
        pcap_perror(ctx->i_pcap_hdl, NULL);
        return -1;
    }

    return 0;
}

static void uninit(ctx_t *ctx)
{
    struct elm_st *elm;

    if (ctx->i_pcap_hdl)
        pcap_close(ctx->i_pcap_hdl);

    SLIST_FOREACH(elm, &ctx->edev_hdr, le) {
        if (elm->e_pcap_hdl)
            pcap_close(elm->e_pcap_hdl);
    }
}

static int run(ctx_t *ctx)
{
    signal(SIGINT, sig_handler);

    if (init_ingress(ctx) == -1)
        goto error;

    if (init_egress(ctx) == -1)
        goto error;

    if (pcap_loop(ctx->i_pcap_hdl, -1, ctx->callback, (u_char *)ctx) == -1) {
        pcap_perror(ctx->i_pcap_hdl, NULL);
        goto error;
    }

    fprintf(stdout, "\n");
    fprintf(stdout, "%s ingress %d packets captured\n", ctx->idev, ctx->icnt);
    //fprintf(stdout, "egress %d packets sent\n", ctx->ecnt);

    struct elm_st *elm;
    SLIST_FOREACH(elm, &ctx->edev_hdr, le) {
        fprintf(stdout, "%s egress %d packets sent\n", elm->edev, elm->ecnt);
    }

    uninit(ctx);
    return 0;

error:
    uninit(ctx);
    return -1;
}

static void usage(const char *bin)
{
    fprintf(stderr, "version 0.1, %s %s\n", __DATE__, __TIME__);
    fprintf(stderr, "Usage: %s [-h] [-i <ingress device>] [-e <egress device>] [-f 'udp dst port 5201']\n", bin);
}

static int parse_arguments(ctx_t *ctx, int argc, char **argv)
{
    int op;

    while ((op = getopt_long(argc, argv, SHORTOPTS, longopts, NULL)) != -1) {
        switch (op) {
            case 'i':
                ctx->idev = strdup(optarg);
                break;
            case 'e': {
                struct elm_st *elm;
                for (int i = optind - 1; i < argc && argv[i][0] != '-'; i++) {
                    elm = (struct elm_st *)malloc(sizeof(struct elm_st));
                    if (!elm)
                        errexit(NULL, "create list error");

                    memset(elm, 0, sizeof(struct elm_st));
                    elm->edev = strdup(argv[i]);
                    SLIST_INSERT_HEAD(&ctx->edev_hdr, elm, le);
                }
                break;
            }
            case 'f':
                ctx->bpf = strdup(optarg);
                break;
            case 'h':
            default:
                return -1;
        }
    }

    //fprintf(stdout, "set idev '%s', bpf '%s'\n", ctx->idev, ctx->bpf);
    return 0;
}

int main(int argc, char *argv[])
{
#ifdef CPU_AFFINITY
    setpriority
    sched_getaffinity
    sched_setaffinity
#endif

    ctx = new_ctx();
    if (!ctx)
        errexit(NULL, "create ctx error - %s", istrerror(ierrno));

    set_defaults(ctx);

    if (parse_arguments(ctx, argc, argv) < 0) {
        //err(test, "parameter error - %s", iperf_strerror(i_errno));
        //usage(stdout);
        usage(argv[0]);
        return 0;
    }

    if (run(ctx) < 0)
        errexit(ctx, "%s", istrerror(ierrno));

    //delete_ctx(ctx);
    return 0;
}
