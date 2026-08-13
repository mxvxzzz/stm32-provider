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

# config ( dev / release ) ( afalg / cryptodev )
BUILD ?= dev
BACKEND ?= afalg

TARGET = stm32prov.so
SRCS = prov.c \
       err.c \
       digest/digest.c \
       hmac/hmac.c \
       cipher/cipher.c \
       aead/aead.c \
       libprov/err.c \
       libprov/num.c

ifeq ($(BACKEND),afalg)
SRCS += digest/hash_afalg.c
SRCS += hmac/hmac_afalg.c
SRCS += cipher/cipher_afalg.c
SRCS += aead/aead_afalg.c
CPPFLAGS += -DBACKEND_AFALG # SHA3 in digest.c
endif

ifeq ($(BACKEND),cryptodev)
SRCS += digest/hash_devcrypto.c
SRCS += hmac/hmac_devcrypto.c
SRCS += cipher/cipher_devcrypto.c
SRCS += aead/aead_devcrypto.c
CPPFLAGS += -I./warning/include # tempo(SDK)  -I/usr/local/include/
CPPFLAGS += -DBACKEND_CRYPTODEV # SHA3 not available for cryptodev / in digest.c
endif

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

