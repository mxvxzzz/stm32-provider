#ifndef CIPHER_H
#define CIPHER_H

#include <openssl/core.h>
#include <openssl/types.h>
#include <stddef.h>

typedef enum {
	STM32_CIPHER_MODE_ECB,
	STM32_CIPHER_MODE_CBC,
	STM32_CIPHER_MODE_CTR
} STM32_CIPHER_MODE;	

#define STM32_AES_BLOCK_SIZE 16U

typedef struct __stm32_cipher_hw_ctx_st__ STM32_CIPHER_HW_CTX;

STM32_CIPHER_HW_CTX *stm32_cipher_newctx(void *provctx, const char *alg_name,
					STM32_CIPHER_MODE mode, size_t keylen);

void stm32_cipher_freectx(STM32_CIPHER_HW_CTX *ctx);

int stm32_cipher_init(STM32_CIPHER_HW_CTX *ctx, const unsigned char *key, size_t keylen,
			const unsigned char *iv, size_t ivlen, int encrypt);

int stm32_cipher_update(STM32_CIPHER_HW_CTX *ctx, unsigned char *out, size_t *outl,
			const unsigned char *in, size_t inl);

int stm32_cipher_final(STM32_CIPHER_HW_CTX *ctx, unsigned char *out, size_t *outl);


/*
 * AEAD gcm ccm (another dispatch table OpenSSL )
 */

#endif /* CIPHER_H */
