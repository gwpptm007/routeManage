TARGET=zrouter
LIB_SO=libzrouter.so
SRCFILE=$(wildcard src/*.c)
OBJFILE=$(patsubst %.c,%.o,$(SRCFILE))

CC=gcc
FLAGS=-Wall
INCLUDE += -Iinc  
LIB_PATH+=
LIB+=
SO_CFLAGS+=-shared -fPIC

#add_right := $(shell sh -c '../src/mkreleasehdr.sh')

INC_DIR = inc
SRC_DIR = src

all:$(LIB_SO) $(TARGET)

$(LIB_SO):$(OBJFILE)
	$(CC) -o $@ $^ $(FLAGS) $(SO_CFLAGS) $(INCLUDE) $(LIB_PATH) $(LIB)
	sudo setcap 'cap_net_admin+ep' $(LIB_SO)

$(TARGET):$(OBJFILE)
	$(CC) -o $@ $^ $(FLAGS) $(INCLUDE) $(LIB_PATH) $(LIB)
	sudo setcap 'cap_net_admin+ep' $(TARGET)

#%.o:%.c
#	$(CC) -c $< $(FLAGS) $(SO_CFLAGS) $(INCLUDE) 
$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) -c $< -o $@ $(FLAGS) $(SO_CFLAGS) -I$(INC_DIR)
	
.PHONY:clean
clean:
	rm -f $(OBJFILE) 
	rm -f $(TARGET) 
	rm -f $(LIB_SO)