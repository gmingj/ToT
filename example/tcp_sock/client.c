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

#define MAX(a,b) (((a) > (b)) ? (a) : (b))
#define MIN(a,b) (((a) < (b)) ? (a) : (b))

#define PKT_SIZE 100
#define BUFF_SIZE 500

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

static void dispaly_latency_cnt(int total)
{
    int i;
    for (i = 0; i < sizeof(lc)/sizeof(lc[0]); i++) {
        printf("%d ", lc[i].sum * PKT_SIZE / total);
    }
    printf("\n");
}

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

int main(int argc, char *argv[])
{
    int sockfd;
    struct sockaddr_in servaddr;
    time_t start_tm = time(NULL);
    int total_pkt = atoi(argv[2]);

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd == -1) {
        perror("socket");
        exit(1);
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(1234);
    servaddr.sin_addr.s_addr = inet_addr(argv[1]);

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect");
        exit(1);
    }
    printf("connected\n");

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
    static long long dbg_max, dbg_min;

    while (packets_sent < total_pkt) {

        timestamp_s = get_timestamp(1000);
        memcpy(buff, &timestamp_s, sizeof(timestamp_s));
        memcpy(buff + sizeof(timestamp_s), &index_s, sizeof(index_s));

        unsigned long long dbg_ts = get_timestamp(1);
        ret = send(sockfd, buff, PKT_SIZE, 0);
        if (ret != PKT_SIZE) {
            perror("send");
            exit(1);
        }
        unsigned long long dbg_diff = get_timestamp(1) - dbg_ts;
        dbg_max = dbg_diff > dbg_max ? dbg_diff : dbg_max;
        dbg_min = dbg_diff < dbg_max ? dbg_diff : dbg_max;
        packets_sent++;
        printf("send: pkt %d timestamp %lld, rcvd_len %d, total sent pkt %d\n",
                index_s, timestamp_s, ret, packets_sent);
        index_s++;

        ret = recv(sockfd, buff, BUFF_SIZE, 0);
        if (ret == -1) {
            perror("recv");
            exit(1);
        }

        memcpy(&timestamp_r, buff, sizeof(timestamp_r));
        memcpy(&index_r, buff + sizeof(timestamp_s), sizeof(index_r));
        if (memcmp(&timestamp_s, &timestamp_r, sizeof(unsigned long long)) != 0) {
            printf("[WARNING] pkt %d not match, sent %lld, recvd %lld !\n", index_r, timestamp_s, timestamp_r);
            continue;
        }

        packets_received++;
        printf("recv: pkt %d timestamp %lld, rcvd_len %d, total rcvd pkt %d\n", index_r, timestamp_r, ret, packets_received);

        ts_now = get_timestamp(1000);
        latency = ts_now - timestamp_s;
        count_latency(latency);

        total_latency += latency;
        min_latency = MIN(min_latency, latency);
        max_latency = MAX(max_latency, latency);

        usleep(20000);
    }

    printf("\n");
    printf("Build at %s %s\n", __DATE__, __TIME__);
    //printf("Packet sent rate %.2f kbps\n", (double)(packets_sent * PKT_SIZE * 8) / (time(NULL) - start_tm) / 1000);
    printf("Total time %ld s\n", time(NULL) - start_tm);
    printf("Total Rx/Tx: %d/%d\n", packets_received, packets_sent);
    printf("Average latency: %d ms\n", total_latency / packets_received);
    printf("Min latency: %d ms\n", min_latency);
    printf("Max latency: %d ms\n", max_latency);
    printf("Send max %lld min %lld\n", dbg_max, dbg_min);
    dispaly_latency_cnt(total_pkt);

    close(sockfd);
    return 0;
}

