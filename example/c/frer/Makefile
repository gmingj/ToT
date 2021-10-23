
#CROSS_COMPILE=/opt/gcc-arm-9.2-2019.12-x86_64-aarch64-none-linux-gnu/bin/aarch64-none-linux-gnu-

CC=$(CROSS_COMPILE)gcc

ifdef CROSS_COMPILE
	ARCH=arm
else
	ARCH=x86
endif

BIN=frer
SRC_PATH=.
OBJ_PATH=obj
LIB_PATH=lib/$(ARCH)
INC_PATH=include
IFLAGS=-I$(INC_PATH)
CFLAGS=-c -Wall -g
LFLAGS=-L$(LIB_PATH) -lpcap -lpthread

SOURCES=$(foreach dir, $(SRC_PATH), $(wildcard $(dir)/*.c))
OBJS=$(addprefix $(OBJ_PATH)/, $(patsubst %.c, %.o, $(notdir $(SOURCES))))
VPATH=$(SRC_PATH) #$(LIB_SRC_PATH)

ifeq ($(DEBUG), y)
	CFLAGS+=-DDEBUG
endif

all:$(BIN)

$(BIN): $(OBJS) #$(LIB_TARGET)
	$(CC) $^ $(LFLAGS) -o $@

$(OBJ_PATH)/%.o:%.c
	@if [ ! -d $(OBJ_PATH) ]; then mkdir -p $(OBJ_PATH); fi;
	$(CC) $(CFLAGS) $< $(IFLAGS) -o $@

.PHONY:echo
echo:
	@echo $(SRC_PATH) $(SOURCES) $(OBJS)

.PHONY:clean
clean:
	@if [ -d $(OBJ_PATH) ]; then rm -rf $(OBJ_PATH); fi
	@if [ -f $(LIB_TARGET) ]; then rm -rf $(LIB_TARGET); fi
	@if [ -f $(BIN) ]; then rm -rf $(BIN); fi
