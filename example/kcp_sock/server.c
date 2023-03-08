#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "ikcp.h"

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

#if 1
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
#endif

int main(int argc, char *argv[])
{
    struct sockaddr_in servaddr, cliaddr;
    int clifd;
    socklen_t clilen = sizeof(struct sockaddr);

    if ((clifd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("socket");
        exit(1);
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(1234);
    if (bind(clifd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind");
        exit(1);
    }

    printf("ready to recv from client\n");

    char buff[BUFF_SIZE];
    int packets_received = 0;
    unsigned long long timestamp;
    int ret;

#if 0
    /*
     * Set the timeout period of 1 seconds, if the value is too small,
     * packets will be out of order, resulting in the failure to count RTT
     *
     */
    struct timeval tv = {1, 0};
    setsockopt(clifd, SOL_SOCKET, SO_RCVTIMEO,
            (char *)&tv, sizeof(struct timeval));
#endif

    int on = 1;
    setsockopt(clifd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    set_nonblock(clifd);

    /* ikcp init */
    user_data_t data = {clifd, (struct sockaddr *)&cliaddr};
    ikcpcb *kcp = ikcp_create(0x11223344, &data);
    kcp->output = udp_output_cb;
    ikcp_wndsize(kcp, 128, 128);
    ikcp_nodelay(kcp, 1, 10, 2, 1);
    kcp->rx_minrto = 10;
    kcp->fastresend = 1;

    while (1) {

        ikcp_update(kcp, get_timestamp(1000));

        ret = recvfrom(clifd, buff, BUFF_SIZE, 0,
                (struct sockaddr *)&cliaddr, &clilen);
        if (ret < 0)
            continue;

        ikcp_input(kcp, buff, ret);
        ret = ikcp_recv(kcp, buff, BUFF_SIZE);
        if (ret < 0)
            continue;

        packets_received++;
        memcpy(&timestamp, buff, sizeof(timestamp));
        unsigned int index_r;
        memcpy(&index_r, buff + sizeof(timestamp), sizeof(index_r));
        printf("recv: pkt %d timestamp %lld, rcvd_len %d, total rcvd pkt %d\n", index_r, timestamp, ret, packets_received);

        ikcp_send(kcp, buff, PKT_SIZE);
        ikcp_flush(kcp);
    }

    close(clifd);
    return 0;
}

