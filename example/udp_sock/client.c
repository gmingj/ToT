#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#define MAX(a,b) (((a) > (b)) ? (a) : (b))
#define MIN(a,b) (((a) < (b)) ? (a) : (b))

#define BUFF_SIZE 500
#define TOTAL_PKT_NUM 500

typedef struct {
	int max;
	int sum;
} latency_count_t;

latency_count_t lc[] = {
	{250},{300},{350},{400},{450},{500},{550},{600},{650},{700},{750},{800},{850},{900},{950},{1000}
};

static void count_latency(int latency)
{
    int i;
    for (i = 0; i < sizeof(lc)/sizeof(lc[0]); i++) {
        if (latency <= lc[i].max)
            lc[i].sum += 1;
    }
}

static void dispaly_latency_cnt(void)
{
    int i;
    for (i = 0; i < sizeof(lc)/sizeof(lc[0]); i++) {
        printf("%d ", lc[i].sum * 100 / TOTAL_PKT_NUM);
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
	int sockfd;
	struct sockaddr_in servaddr, addr;
    time_t start_tm = time(NULL);
	socklen_t servlen = sizeof(struct sockaddr), addrlen = sizeof(struct sockaddr);

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
    struct timespec ts;
    unsigned long long timestamp_s, timestamp_r, ts_now;
    char buff[BUFF_SIZE];
    int ret;
    int latency;

    /* for tc */
    struct timeval tv = {0, 200000};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
            (char *)&tv, sizeof(struct timeval));

    while (packets_received < TOTAL_PKT_NUM) {

        clock_gettime(CLOCK_MONOTONIC, &ts);
        timestamp_s = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
        memcpy(buff, &timestamp_s, sizeof(timestamp_s));

        ret = sendto(sockfd, buff, 100, 0,
                (struct sockaddr *)&servaddr, servlen);
        if (ret != 100) {
            perror("sendto");
            exit(1);
        }
        packets_sent++;

resend:
        ret = recvfrom(sockfd, buff, BUFF_SIZE, 0,
                (struct sockaddr *)&addr, &addrlen);
        if (ret == -1 && errno == EAGAIN) {
            continue;
        }
        if (ret == -1) {
            perror("recvfrom");
            exit(1);
        }

        memcpy(&timestamp_r, buff, sizeof(timestamp_r));

        if (memcmp(&timestamp_s, &timestamp_r, sizeof(unsigned long long)) != 0) {
            //printf("[WARNING] pkt not match !\n");
            goto resend;
        }
        
        printf("recv: timestamp_r %lld, rcvd_len %d\n", timestamp_r, ret);

        clock_gettime(CLOCK_MONOTONIC, &ts);
        ts_now = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
        latency = ts_now - timestamp_s;
        count_latency(latency);

        total_latency += latency;
        min_latency = MIN(min_latency, latency);
        max_latency = MAX(max_latency, latency);
        packets_received++;
    }

    printf("\n");
    printf("Total time %ld s\n", time(NULL) - start_tm);
    printf("Total Rx/Tx: %d/%d\n", packets_received, packets_sent);
    printf("Average latency: %d ms\n", total_latency / packets_received);
    printf("Min latency: %d ms\n", min_latency);
    printf("Max latency: %d ms\n", max_latency);
    dispaly_latency_cnt();

    close(sockfd);
    return 0;
}

