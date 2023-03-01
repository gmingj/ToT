
CFLAGS=-g -Wall
BUILD_PATH=build

all:$(BUILD_PATH)/tcpclient $(BUILD_PATH)/tcpserver

$(BUILD_PATH)/tcpserver:server.c
	@if [ ! -d $(BUILD_PATH) ]; then mkdir -p $(BUILD_PATH); fi;
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_PATH)/tcpclient:client.c
	@if [ ! -d $(BUILD_PATH) ]; then mkdir -p $(BUILD_PATH); fi;
	$(CC) $(CFLAGS) $^ -o $@

.PHONY:
clean:
	-rm -rf $(BUILD_PATH)
