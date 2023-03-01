
CFLAGS=-g -Wall
BUILD_PATH=build

all:$(BUILD_PATH)/udpclient $(BUILD_PATH)/udpserver

$(BUILD_PATH)/udpserver:server.c
	@if [ ! -d $(BUILD_PATH) ]; then mkdir -p $(BUILD_PATH); fi;
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_PATH)/udpclient:client.c
	@if [ ! -d $(BUILD_PATH) ]; then mkdir -p $(BUILD_PATH); fi;
	$(CC) $(CFLAGS) $^ -o $@

.PHONY:
clean:
	-rm -rf $(BUILD_PATH)
