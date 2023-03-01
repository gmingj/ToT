#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <linux/if_ether.h>

#include <pcap/pcap.h>

#define TIMEOUT 100
#define SHORTOPTS "hdf:F:o:m:rt:n:"
#define INTERVAL_USEC 2000

typedef struct {
    char *fname;
    char *dev_out;
    char *bpf;
    pcap_t *pcap_hdl_in;
    pcap_t *pcap_hdl_out;
    int icnt;
    int ocnt;
    int debug;
    int rflg;
    int tm;
} ctx_t;

static int pno = 0;
static int sig_exit;
static pcap_t *gpcap_hdl;

static const struct option longopts[] = {
    { "help", no_argument, NULL, 'h' },
    { "debug", no_argument, NULL, 'd' },
    { "repeat", no_argument, NULL, 'r' },
    { "time-interval", no_argument, NULL, 't' },
    { "file-name", required_argument, NULL, 'f' },
    { "packet-filter", required_argument, NULL, 'F' },
    { "out-interface", required_argument, NULL, 'o' },
    { "pack-number", required_argument, NULL, 'n' },
	{ 0, 0, 0, 0 },
};

static ctx_t *new_ctx(void)
{
    ctx_t *ctx = malloc(sizeof(ctx_t));
    if (!ctx) {
        return NULL;
    }

    memset(ctx, 0, sizeof(ctx_t));
    return ctx;
}

static void usage(const char *bin)
{
    fprintf(stderr, "version 1.3.0, %s %s\n", __DATE__, __TIME__);
    fprintf(stderr, "Usage: %s [-f <file>] [-o <device>] [-F <packet-filter>] [-r] [-h] [-d]\n", bin);
    fprintf(stderr, "Examples: %s -f xxx.cap -o eth1 -F 'udp dst port 1122'\n", bin);
}

static int parse_arguments(ctx_t *ctx, int argc, char **argv)
{
    int op;

    while ((op = getopt_long(argc, argv, SHORTOPTS, longopts, NULL)) != -1) {
        switch (op) {
            case 'd':
                ctx->debug = 1;
                break;
            case 'n':
                pno = atoi(optarg);
                break;
            case 'f':
                ctx->fname = strdup(optarg);
                break;
            case 'F':
                ctx->bpf = strdup(optarg);
                break;
            case 'o':
                ctx->dev_out = strdup(optarg);
                break;
            case 'r':
                ctx->rflg = 1;
                break;
            case 't':
                ctx->tm = atoi(optarg);
                break;
            case 'h':
            default:
                return -1;
        }
    }

    if (!ctx->fname || !ctx->dev_out)
        return -1;

    if (ctx->tm == 0)
        ctx->tm = INTERVAL_USEC;

    return 0;
}

void sig_handler(int signo)
{
    pcap_breakloop(gpcap_hdl);
    sig_exit = 1;
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

static void proc_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    ctx_t *ctx = (ctx_t *)user;
    static int id = 0;

    //if (ctx->debug)
    //    fprintf(stderr, "Captured: len(%d) %s\n\n", h->len, hexdump(bytes, 46));

    id++;
    if (id != pno) {
        return;
    }

    ctx->icnt += 1;

    if (ctx->debug)
        fprintf(stderr, "TX(%d):%s\n", h->len, hexdump(bytes, 24));

    if (pcap_sendpacket(ctx->pcap_hdl_out, bytes, h->len) != 0) {
        if (ctx->debug)
            pcap_perror(ctx->pcap_hdl_out, NULL);

        return;
    }
    ctx->ocnt += 1;
    usleep(ctx->tm);

}

int main(int argc, char *argv[])
{
    ctx_t *ctx;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program bp;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGHUP, sig_handler);

    ctx = new_ctx();
    if (!ctx) {
        fprintf(stderr, "error: new ctx\n");
        return -1;
    }

    if (parse_arguments(ctx, argc, argv) < 0) {
        usage(argv[0]);
        exit(-1);
    }

    ctx->pcap_hdl_out = pcap_open_live(ctx->dev_out, BUFSIZ, 0, TIMEOUT, errbuf);
    if (!ctx->pcap_hdl_out) {
        fprintf(stderr, "%s\n", errbuf);
        return -1;
    }

    do {
        ctx->pcap_hdl_in = pcap_open_offline(ctx->fname, errbuf);
        if (!ctx->pcap_hdl_in) {
            fprintf(stderr, "%s\n", errbuf);
            return -1;
        }
        gpcap_hdl = ctx->pcap_hdl_in;

        if (pcap_compile(ctx->pcap_hdl_in, &bp, ctx->bpf, 0, -1) == -1) {
            pcap_perror(ctx->pcap_hdl_in, NULL);
            goto error;
        }

        if (pcap_setfilter(ctx->pcap_hdl_in, &bp) == -1) {
            pcap_perror(ctx->pcap_hdl_in, NULL);
            goto error;
        }

        (void)pcap_loop(ctx->pcap_hdl_in, -1, proc_packet, (u_char *)ctx);
        pcap_close(ctx->pcap_hdl_in);
    } while (ctx->rflg && !sig_exit);

    fprintf(stdout, "\n");
    fprintf(stdout, "%d packets captured\n", ctx->icnt);
    fprintf(stdout, "%d packets sent\n", ctx->ocnt);

    return 0;

error:
    if (ctx->pcap_hdl_in)
        pcap_close(ctx->pcap_hdl_in);

    if (ctx->pcap_hdl_out)
        pcap_close(ctx->pcap_hdl_out);

    return -1;
}
