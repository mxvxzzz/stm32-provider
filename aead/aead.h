#ifndef AEAD_H
#define AEAD_H

#include <openssl/core.h>
#include <stddef.h>

#define GCM_IV_SIZE   12
#define CCM_IV_SIZE   12
#define MAX_TAG_SIZE  16
#define MAX_AAD_SIZE  (64 * 1024)

typedef enum {
  STM32_AEAD_MODE_GCM,
  STM32_AEAD_MODE_CCM
} STM32_AEAD_MODE;

typedef struct stm32_aead_hw_ctx_st STM32_AEAD_HW_CTX;

STM32_AEAD_HW_CTX *stm32_aead_newctx(void *provctx, const char *alg_name,
				      STM32_AEAD_MODE mode, size_t keylen);

void stm32_aead_freectx(STM32_AEAD_HW_CTX *ctx);


int stm32_aead_init(STM32_AEAD_HW_CTX *ctx, const unsigned char *key,
		     size_t keylen, size_t taglen, int encrypt);

extern const OSSL_ALGORITHM stm32_aead_ciphers[];

#endif /* AEAD_H */