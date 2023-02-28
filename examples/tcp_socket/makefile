
all:tcpclient tcpserver

tcpserver:server.c
	$(CC) $^ -o $@

tcpclient:client.c
	$(CC) $^ -o $@

.PHONY:
clean:
	-rm -f *.o tcpclient tcpserver
