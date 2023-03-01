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
	int listenfd, connfd;
	socklen_t clilen;

	if ((listenfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket");
		exit(1);
	}

	bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(1234);
	if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
		perror("bind");
		exit(1);
	}

	if (listen(listenfd, 1) < 0) {
		perror("listen");
		exit(1);
	}

    clilen = sizeof(cliaddr);
    printf("ready to accept...\n");
    if ((connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &clilen)) < 0) {
        perror("accept");
        exit(1);
    }
    printf("accepted client %s\n", inet_ntoa(cliaddr.sin_addr));

    char buff[BUFF_SIZE];
    int packets_received = 0;
    unsigned long long timestamp;
    int ret;

    while (1) {

        ret = recv(connfd, buff, BUFF_SIZE, 0);
        if (ret == -1) {
            perror("recv");
            exit(1);
        }
        if (ret == 0) {
            printf("peer closed\n");
            exit(0);
        }
        packets_received++;

        memcpy(&timestamp, buff, sizeof(timestamp));
        printf("recv: timestamp %lld, rcvd_len %d, total rcvd pkt %d\n", timestamp, ret, packets_received);

        ret = send(connfd, buff, 100, 0);
        if (ret != 100) {
            perror("send");
            exit(1);
        }
    }

    close(listenfd);
    return 0;
}

