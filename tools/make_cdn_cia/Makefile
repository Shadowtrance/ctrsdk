CC = gcc
CFLAGS = -O2 -Wall -std=c11
TARGET = make_cdn_cia
OBJS = main.o cia.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(OBJS) $(TARGET)
