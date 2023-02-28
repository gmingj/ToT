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

#define MAX(a,b) (((a) > (b)) ? (a) : (b))
#define MIN(a,b) (((a) < (b)) ? (a) : (b))

#define BUFF_SIZE 500

int main(int argc, char *argv[])
{
	int sockfd;
	struct sockaddr_in servaddr;
    int test_duration = atoi(argv[2]);

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd == -1) {
        perror("socket");
        exit(1);
    }

	bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(1234);
	if (inet_pton(AF_INET, argv[1], &servaddr.sin_addr) < 0) {
		printf("inet_pton error for %s\n", argv[1]);
		exit(1);
	}

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect");
        exit(1);
    }
    printf("connected\n");

    int start_time = time(NULL);
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

    while (time(NULL) < start_time + test_duration) {

        clock_gettime(CLOCK_MONOTONIC, &ts);
        timestamp_s = ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
        memcpy(buff, &timestamp_s, sizeof(timestamp_s));

        ret = send(sockfd, buff, 100, 0);
        if (ret != 100) {
            perror("send");
            exit(1);
        }
        packets_sent++;

        ret = recv(sockfd, buff, BUFF_SIZE, 0);
        if (ret == -1) {
            perror("recv");
            exit(1);
        }

        memcpy(&timestamp_r, buff, sizeof(timestamp_r));
        printf("recv: timestamp_r %lld, rcvd_len %d\n", timestamp_r, ret);

        if (memcmp(&timestamp_s, &timestamp_r, sizeof(unsigned long long)) != 0) {
            printf("[WARNING] pkt not match !\n");
            exit(1);
        }

        clock_gettime(CLOCK_MONOTONIC, &ts);
        ts_now = ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
        latency = ts_now - timestamp_s;
        total_latency += latency;
        min_latency = MIN(min_latency, latency);
        max_latency = MAX(max_latency, latency);
        packets_received++;
    }

    printf("\n");
    printf("Total Rx/Tx: %d/%d\n", packets_received, packets_sent);
    printf("Average latency: %d us\n", total_latency / packets_received);
    printf("Min latency: %d us\n", min_latency);
    printf("Max latency: %d us\n", max_latency);
    
    close(sockfd);
    return 0;
}

