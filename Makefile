CC = gcc
CFLAGS = -Wall -Wextra -fPIC
LDFLAGS = -shared -lcrypto
TARGET = stm32_provider.so
SRCS = stm32prov.c
OBJS = stm32prov.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

stm32prov.o: stm32prov.c
	$(CC) $(CFLAGS) -c stm32prov.c -o stm32prov.o

clean:
	rm -f $(OBJS) $(TARGET)
