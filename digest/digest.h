#ifndef DIGEST_H
#define DIGEST_H


#include <openssl/core.h>

/*********************************************************************
 *
 *  Operations digest AF_ALG 
 *  socket context / binding / accept / send / read
 *****/

/* Opaque type for the AF_ALG hash context 
 *
 *  Provider global context
 *      PROV_CTX
 *          └── proverr_handle
 *
 *  Hash operation context
 *      STM32_HASH_CTX
 *          └── provctx ---> PROV_CTX
 *
 *****/
typedef struct stm32_hash_ctx_st STM32_HASH_CTX;

/*********************************************************************
 *
 *  AF_ALG hash interface used by digest.c 
 *
 *****/
STM32_HASH_CTX *stm32_hash_newctx(void *provctx, const char *alg_name,
                                  size_t digest_size);
void stm32_hash_freectx(STM32_HASH_CTX *ctx);
int stm32_hash_init(STM32_HASH_CTX *ctx);
int stm32_hash_update(STM32_HASH_CTX *ctx, const unsigned char *in, size_t inl);
int stm32_hash_final(STM32_HASH_CTX *ctx, unsigned char *out, size_t *outl);

/*********************************************************************
 *
 *  Table of digest algorithms 
 *
 *****/
extern const OSSL_ALGORITHM stm32_digests[];


#endif /* DIGEST_H */