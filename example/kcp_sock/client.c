#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <errno.h>

#include "ikcp.h"

#define MAX(a,b) (((a) > (b)) ? (a) : (b))
#define MIN(a,b) (((a) < (b)) ? (a) : (b))

#define PKT_SIZE 100
#define BUFF_SIZE 500

typedef struct {
    int sockfd;
    struct sockaddr *servaddr;
} user_data_t;

/*
 * ms: scale = 1000
 * us: scale = 1
 */
static unsigned long long get_timestamp(int scale)
{
    struct timeval tv;

    if (gettimeofday(&tv, NULL) != 0) {
        perror("gettimeofday");
        exit(1);
    }

    return tv.tv_sec * 1000 * (1000 / scale) + tv.tv_usec / scale;
}

static int udp_output_cb(const char *buf, int len, ikcpcb *kcp, void *user)
{
    int ret;
    user_data_t *data = (user_data_t *)user;

    ret = sendto(data->sockfd, buf, len, 0, data->servaddr, sizeof(struct sockaddr));
    if (ret == -1) {
        perror("sendto");
    }
    return ret;
}

static void set_nonblock(int sockfd)
{
    int flag = fcntl(sockfd, F_GETFL, 0);
    if (flag < 0) {
        perror("fcntl");
        exit(1);
    }

    if (fcntl(sockfd, F_SETFL, flag | O_NONBLOCK) < 0) {
        perror("fcntl");
        exit(1);
    }
}

int main(int argc, char *argv[])
{
    int sockfd;
    struct sockaddr_in servaddr, addr;
    socklen_t addrlen = sizeof(struct sockaddr);
    int total_pkt = atoi(argv[2]);

    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd == -1) {
        perror("socket");
        exit(1);
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(1234);
    servaddr.sin_addr.s_addr = inet_addr(argv[1]);

    int total_latency = 0;
    int min_latency = INT_MAX;
    int max_latency = 0;
    int packets_sent = 0;
    int packets_received = 0;
    unsigned long long timestamp_s, timestamp_r, ts_now;
    char buff[BUFF_SIZE];
    int ret;
    int latency;
    unsigned int index_s = 0, index_r;

#if 0
    /*
     * Set the timeout period of 1 seconds, if the value is too small,
     * packets will be out of order, resulting in the failure to count RTT
     */
    struct timeval tv = {1, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
            (char *)&tv, sizeof(struct timeval));
#endif

    //int on = 1;
    //setsockopt(clifd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    set_nonblock(sockfd);

    /* ikcp init */
    user_data_t data = {sockfd, (struct sockaddr *)&servaddr};
    ikcpcb *kcp = ikcp_create(0x11223344, &data);
    kcp->output = udp_output_cb;
    ikcp_wndsize(kcp, 128, 128);
    ikcp_nodelay(kcp, 1, 10, 2, 1);
    kcp->rx_minrto = 10;
    kcp->fastresend = 1;

    timestamp_s = get_timestamp(1);
    memcpy(buff, &timestamp_s, sizeof(timestamp_s));
    memcpy(buff + sizeof(timestamp_s), &index_s, sizeof(index_s));

    time_t start_tm = get_timestamp(1000);
    ikcp_send(kcp, buff, PKT_SIZE);
    ikcp_flush(kcp);

    while (packets_sent < total_pkt) {

        usleep(10);

        ikcp_update(kcp, get_timestamp(1000));

        ret = recvfrom(sockfd, buff, BUFF_SIZE, MSG_DONTWAIT,
                (struct sockaddr *)&addr, &addrlen);
        if (ret < 0)
            continue;

        //printf("ikcp_input %d bytes\n", ret);
        ikcp_input(kcp, buff, ret);

        ret = ikcp_recv(kcp, buff, BUFF_SIZE);
        if (ret < 0)
            continue;

        memcpy(&timestamp_r, buff, sizeof(timestamp_r));
        memcpy(&index_r, buff + sizeof(timestamp_s), sizeof(index_r));
        if (memcmp(&timestamp_s, &timestamp_r, sizeof(unsigned long long)) != 0) {
            printf("[WARNING] pkt not match, sent %lld, recvd %lld !\n", timestamp_s, timestamp_r);
            exit(1);
        }

        packets_received++;
        //printf("recv: pkt %d timestamp %lld, rcvd_len %d, total rcvd pkt %d\n", index_r, timestamp_r, ret, packets_received);

        ts_now = get_timestamp(1);
        latency = ts_now - timestamp_s;
        printf("%.3f ", (double)latency / 1000);
        //count_latency(latency);

        total_latency += latency;
        min_latency = MIN(min_latency, latency);
        max_latency = MAX(max_latency, latency);

        timestamp_s = get_timestamp(1);
        memcpy(buff, &timestamp_s, sizeof(timestamp_s));
        memcpy(buff + sizeof(timestamp_s), &index_s, sizeof(index_s));

        ikcp_send(kcp, buff, PKT_SIZE);
        ikcp_flush(kcp);
        packets_sent++;
        //printf("send: pkt %d timestamp %lld, rcvd_len %d, total sent pkt %d\n",
        //        index_s, timestamp_s, PKT_SIZE, packets_sent);
        index_s++;
    }

    printf("\n");
    printf("--- statistics ---\n");
    double elapsed_time = (double)(get_timestamp(1000) - start_tm) / 1000;
    printf("%d packets transmitted, %d received, %d packet loss, time %.3f s\n",
            packets_sent,
            packets_received,
            packets_sent - packets_received,
            elapsed_time);
    printf("rtt min/avg/max = %.3f/%.3f/%.3f ms\n",
            (double)min_latency / 1000,
            (double)total_latency / packets_received / 1000,
            (double)max_latency / 1000);
    printf("throughout %.3f bps\n", (double)((packets_sent + packets_received) * 8) / elapsed_time);

    close(sockfd);
    return 0;
}

