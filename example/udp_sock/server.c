#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define BUFF_SIZE 500

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

    while (1) {

        ret = recvfrom(clifd, buff, BUFF_SIZE, 0,
                (struct sockaddr *)&cliaddr, &clilen);
        if (ret == -1) {
            perror("recvfrom");
            exit(1);
        }
        if (ret == 0) {
            printf("peer closed\n");
            exit(0);
        }
        packets_received++;

        memcpy(&timestamp, buff, sizeof(timestamp));
        printf("recv: timestamp %lld, rcvd_len %d, total rcvd pkt %d\n", timestamp, ret, packets_received);

        ret = sendto(clifd, buff, 100, 0,
                (struct sockaddr *)&cliaddr, sizeof(struct sockaddr));
        if (ret != 100) {
            perror("sendto");
            exit(1);
        }
    }

    close(clifd);
    return 0;
}

