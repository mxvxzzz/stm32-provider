CC = gcc
CFLAGS = -Wall -Wextra -fPIC -I. -I./include -I./libprov/include 
LDFLAGS = -shared \
           $(shell pkg-config --libs libcrypto)
TARGET = stm32_provider.so
SRCS = prov.c \
       err.c \
       digest/digest.c \
       digest/hash_afalg.c \
       libprov/err.c \
       libprov/num.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
