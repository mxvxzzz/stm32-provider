#ifndef AEAD_H
#define AEAD_H

#include <openssl/core.h>
#include <openssl/types.h>
#include <stddef.h>

/* Default nonce lengths advertised by the EVP algorithms */
#define GCM_IV_SIZE          12
//#define CCM_IV_SIZE_MAX    13
#define CCM_IV_DEFAULT       7


#define MAX_TAG_SIZE         16
#define MAX_KEY_SIZE         32
#define MAX_AAD_SIZE         (64 * 1024)

/*
 * IV as passed to the backend (= as expected by the kernel):
 *   - gcm(aes): ivsize = 12, raw nonce
 *   - ccm(aes): ivsize = 16, RFC 3610 formatted block: [L-1][nonce][counter]
 */
#define MAX_IV_SIZE       16

/* Maximum size of single-call with the kernel */
#define MAX_ONESHOT_SIZE     (64 * 1024)

typedef enum {
  STM32_AEAD_MODE_GCM,
  STM32_AEAD_MODE_CCM
} STM32_AEAD_MODE;

/* Error codes of backends */
#define STM32_AEAD_OK          1
#define STM32_AEAD_ERROR       0
#define STM32_AEAD_AUTH_FAIL (-1)   /* decryption : tag invalid */

typedef struct stm32_aead_hw_ctx_st STM32_AEAD_HW_CTX;

STM32_AEAD_HW_CTX *stm32_aead_newctx(void *provctx, const char *alg_name,
				     STM32_AEAD_MODE mode, size_t keylen);

void stm32_aead_freectx(STM32_AEAD_HW_CTX *ctx);

/*
 * stm32_aead_init : set the key and tag size for the upcoming operation.
 * In CCM the tag is part of the B0 block.
 */
int stm32_aead_init(STM32_AEAD_HW_CTX *ctx, const unsigned char *key,
		    size_t keylen, size_t taglen, int encrypt);

int stm32_aead_encrypt(STM32_AEAD_HW_CTX *ctx, const unsigned char *iv, size_t ivlen,
		       const unsigned char *aad, size_t aadlen, const unsigned char *in, 
		       size_t inl, unsigned char *out, size_t *outl, unsigned char *tag, 
		       size_t taglen);

int stm32_aead_decrypt(STM32_AEAD_HW_CTX *ctx, const unsigned char *iv, size_t ivlen,
		       const unsigned char *aad, size_t aadlen, const unsigned char *in,
		       size_t inl, unsigned char *out, size_t *outl, const unsigned char *tag,
		       size_t taglen);

#endif /* AEAD_H */