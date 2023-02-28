#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>

#include <pcap/pcap.h>

#define SNAP_LEN 65536

enum {
    IENONE,                 // No error
    IENEWCXT,               // Unable to malloc
    IEPCAPOPEN,             // Unable to create pcap handle
};

typedef struct {
    pcap_t *ihdl;
    pcap_t *ehdl;
    char *bpf;
    char *idev;
    char *edev;
    int icnt;
    int ecnt;
} ctx_t;

int ierrno;
ctx_t *ctx;

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

static void process_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
#if 0
    struct timeval tvbuf;
    tvbuf.tv_sec = h->ts.tv_sec;
    tvbuf.tv_usec = h->ts.tv_usec;
#endif

#ifdef DEBUG
    fprintf(stdout, "Recvd pkt: len(%d) %s\n\n", h->len, hexdump(bytes, 46));
    //fflush(stdout);
#endif

    ctx_t *ctx = (ctx_t *)user;
    ctx->icnt += 1;

    if (pcap_sendpacket(ctx->ehdl, bytes, h->len) != 0) {
        pcap_perror(ctx->ehdl, NULL);
        return;
    }
    ctx->ecnt += 1;
}

void sig_handler(int sig)
{
    pcap_breakloop(ctx->ihdl);
}

int setup_pcap(ctx_t *ctx)
{
    return 0;
}

static int run(ctx_t *ctx)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask;
    struct bpf_program bpf;

    signal(SIGINT, sig_handler);

    ctx->ehdl = pcap_open_live(ctx->edev, SNAP_LEN, 1, 1000, errbuf);
    if (!ctx->ehdl) {
        fprintf(stderr, "%s\n", errbuf);
        return -1;
    }

    ctx->ihdl = pcap_open_live(ctx->idev, SNAP_LEN, 1, 1000, errbuf);
    if (!ctx->ihdl) {
        fprintf(stderr, "%s\n", errbuf);
        return -1;
    }

    if (pcap_lookupnet(ctx->idev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "%s\n", errbuf);
        return -1;
    }

    if (pcap_compile(ctx->ihdl, &bpf, ctx->bpf, 0, net) == -1) {
        pcap_perror(ctx->ihdl, NULL);
        return -1;
    }

    if (pcap_setfilter(ctx->ihdl, &bpf) == -1) {
        pcap_perror(ctx->ihdl, NULL);
        return -1;
    }

    if (pcap_loop(ctx->ihdl, -1, process_packet, (u_char *)ctx) == -1) {
        pcap_perror(ctx->ihdl, NULL);
        return -1;
    }

    fprintf(stdout, "\n");
    fprintf(stdout, "ingress %d packets captured\n", ctx->icnt);
    fprintf(stdout, "egress %d packets sent\n", ctx->ecnt);

    pcap_close(ctx->ihdl);
    return 0;
}

static void usage(const char *bin)
{
    fprintf(stderr, "version 0.1, %s %s\n", __DATE__, __TIME__);
    fprintf(stderr, "Usage: %s [-h] [-i <ingress device>] [-e <egress device>] [-f 'udp dst port 5201']\n", bin);
}

static int parse_arguments(ctx_t *ctx, int argc, char **argv)
{
    int flag;

    while ((flag = getopt(argc, argv, "hi:e:f:")) != -1) {
        switch (flag) {
            case 'i':
                ctx->idev = strdup(optarg);
                break;
            case 'e':
                ctx->edev = strdup(optarg);
                break;
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
