
CFLAGS=-g -Wall
BUILD_PATH=build

all:$(BUILD_PATH)/kcpclient $(BUILD_PATH)/kcpserver

$(BUILD_PATH)/kcpserver:server.c ikcp.c
	@if [ ! -d $(BUILD_PATH) ]; then mkdir -p $(BUILD_PATH); fi;
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_PATH)/kcpclient:client.c ikcp.c
	@if [ ! -d $(BUILD_PATH) ]; then mkdir -p $(BUILD_PATH); fi;
	$(CC) $(CFLAGS) $^ -o $@

.PHONY:
clean:
	-rm -rf $(BUILD_PATH)
