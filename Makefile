# # # # #
#
#   Main options:
#      -Wall -Wextra : compiler warnings
#      -fPIC         : required for shared library (.so)
#      -MMD -MP      : automatic header dependencies
#   
#   make
#       Build in development mode (default)
#
#   make BUILD=dev
#       -O0 = no optimization
#       -g  = debug symbols
#
#   make BUILD=release
#       -O2 = optimized binary for target
#
#   make clean
#       Remove objects, dependencies and .so
#
# # # # #

#CC = aarch64-ostl-linux-gcc
PKG_CONFIG ?= pkg-config
BUILD ?= dev
TARGET = stm32_provider.so
SRCS = prov.c \
       err.c \
       digest/digest.c \
       digest/hash_afalg.c \
       libprov/err.c \
       libprov/num.c
OBJS = $(SRCS:.c=.o)
DEPS = $(OBJS:.o=.d)

CPPFLAGS += -I. -I./include -I./libprov/include \
            $(shell $(PKG_CONFIG) --cflags libcrypto)

CFLAGS += -Wall -Wextra -fPIC -MMD -MP
ifeq ($(BUILD),dev)
CFLAGS += -O0 -g
endif
ifeq ($(BUILD),release)
CFLAGS += -O2
endif

LDFLAGS += -shared
LDLIBS += $(shell $(PKG_CONFIG) --libs libcrypto)


all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(DEPS) $(TARGET)

-include $(DEPS)

