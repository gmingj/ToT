#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

enum {
    IENONE,                 // No error

    /* System errors */
    IENEWCXT,               // // Unable to malloc

    /* Parameter errors */


};

typedef struct {
} ctx_t;

int ierrno;

const char *istrerror(int errno)
{
    static char str[1024];
    strcpy(str, "NA");
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

static int parse_arguments(ctx_t *ctx, int argc, char **argv)
{
    return 0;
}

static int run(ctx_t *ctx)
{
    return 0;
}

int main(int argc, char *argv[])
{
    ctx_t *ctx;

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
        //fprintf(stderr, "\n");
        //usage_long(stdout);
        exit(1);
    }

    if (run(ctx) < 0)
        errexit(ctx, "error - %s", istrerror(ierrno));

    //delete_ctx(ctx);
    //
    return 0;
}
