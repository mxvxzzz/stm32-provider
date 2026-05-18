#ifndef HMAC_H
#define HMAC_H

#include <openssl/core.h>
#include <openssl/types.h>  // for OSSL_ALGORITHM
#include <stddef.h>         // for size_t

/*
 *  Opaque type for the AF_ALG / Cryptodev hmac context 
 *  HMAC operation context
 *      STM32_HMAC_CTX
 *          └── provctx ---> PROV_CTX
 *
 *****/

 typedef struct __stm32_hmac_ctx_st__ STM32_HMAC_CTX;

/*********************************************************************
 *
 *  AF_ALG / Cryptodev hmac interface used by hmac.c 
 *
 *****/
STM32_HMAC_CTX *stm32_hmac_newctx(void *provctx, const char *alg_name,
                                        size_t digest_size);
void stm32_hmac_freectx(STM32_HMAC_CTX *ctx);
int stm32_hmac_init(STM32_HMAC_CTX *ctx,
                        const unsigned char *key, size_t keylen);
int stm32_hmac_update(STM32_HMAC_CTX *ctx,
                        const unsigned char *in, size_t inl);
int stm32_hmac_final(STM32_HMAC_CTX *ctx,
                        unsigned char *out, size_t *outl);

extern const OSSL_ALGORITHM stm32_macs[];

#endif /* HMAC_H */