#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include "../include/names.h"
#include "../include/prov.h"
#include "../include/err.h"
#include "cipher.h"
#include <openssl/evp.h> /* fix temp : EVP_CIPH_*_MODE */


typedef struct stm32_cipher_ctx_st STM32_CIPHER_CTX_;

/* prototypes of functions */
static void *cipher_newctx(void *provctx, STM32_CIPHER_MODE mode, size_t keylen,
			size_t ivlen, size_t block_size, const char *hw_alg_name);
static void cipher_freectx(void *vctx);

static int cipher_init(STM32_CIPHER_CTX_ *ctx, const unsigned char *key, size_t keylen,
			const unsigned char *iv, size_t ivlen, int encrypt, const OSSL_PARAM params[]);

static int cipher_encrypt_init(void *vctx, const unsigned char *key, size_t keylen,
				const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[]);
static int cipher_decrypt_init(void *vctx, const unsigned char *key, size_t keylen,
				const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[]);

static int cipher_get_params(OSSL_PARAM params[], STM32_CIPHER_MODE mode, size_t keylen, 
			size_t ivlen, size_t block_size);

static const OSSL_PARAM *cipher_gettable_params(void *provctx);
static int cipher_get_ctx_params(void *vctx, OSSL_PARAM params[]);
static const OSSL_PARAM *cipher_gettable_ctx_params(void *vctx, void *provctx);
static int cipher_set_ctx_params(void *vctx, const OSSL_PARAM params[]);
static const OSSL_PARAM *cipher_settable_ctx_params(void *vctx, void *provctx);

/*********************************************************************
 *
 *  OpenSSL provider Cipher context
 *
 *****/

struct stm32_cipher_ctx_st {
	void *provctx;
	STM32_CIPHER_HW_CTX *hw_ctx;
	STM32_CIPHER_MODE mode;
	size_t keylen;
	size_t ivlen;
	size_t block_size;
	const char *hw_alg_name; /* "stm32-cbc-aes" for af_alg (name exposed by the driver stm32 (kernel)) */
	int encrypt;
	int pad_enabled;
	unsigned char key[32];
	unsigned char iv[16];
};

static void *cipher_newctx(void *provctx, STM32_CIPHER_MODE mode, size_t keylen,
			size_t ivlen, size_t block_size, const char *hw_alg_name) {

	PROV_CTX *pctx = (PROV_CTX *)provctx;
	STM32_CIPHER_CTX_ *ctx;
	if (pctx == NULL)
		return NULL;

	ctx = OPENSSL_zalloc(sizeof(*ctx));
	if (ctx == NULL) {
		PUT_ERROR(pctx, STM32_R_CIPHER_NEWCTX_FAILED,
			"failed to allocate cipher context");
		return NULL;
	}

	ctx->provctx = provctx;
	ctx->hw_ctx = NULL; /* key not yet defined || will defined in init() */
	ctx->mode = mode;
	ctx->keylen = keylen;
	ctx->ivlen = ivlen;
	ctx->block_size = block_size;
	ctx->hw_alg_name = hw_alg_name;
	ctx->pad_enabled = (mode == STM32_CIPHER_MODE_CTR) ? 0 : 1;

	return ctx;
}

static void cipher_freectx(void *vctx)
{
	STM32_CIPHER_CTX_ *ctx = (STM32_CIPHER_CTX_ *)vctx;

	if (ctx == NULL)
		return;

	if (ctx->hw_ctx != NULL)
		stm32_cipher_freectx(ctx->hw_ctx);

	OPENSSL_cleanse(ctx->key, sizeof(ctx->key));
	OPENSSL_cleanse(ctx->iv, sizeof(ctx->iv));
	OPENSSL_free(ctx);
}

/*********************************************************************
*
* Init (encrypt/decrypt)
*
*****/
static int cipher_init(STM32_CIPHER_CTX_ *ctx, const unsigned char *key, size_t keylen,
		const unsigned char *iv, size_t ivlen, int encrypt, const OSSL_PARAM params[]) 
{
	PROV_CTX *pctx = (PROV_CTX *)ctx;

	if (pctx == NULL)
		return 0;

	if (params != NULL && !cipher_set_ctx_params(ctx, params))
		return 0;

	if (key != NULL) {
		if (keylen != ctx->keylen) {
			PUT_ERROR(pctx, STM32_R_INVALID_ARGUMENT,
				"invalid key length: got %zu, expected %zu", keylen, ctx->keylen);
			return 0;
		}
		memcpy(ctx->key, key, keylen);
	}

	if (iv != NULL) {
		if (ivlen != ctx->ivlen) {
			PUT_ERROR(pctx, STM32_R_INVALID_ARGUMENT,
				"invalid IV length: got %zu, expected %zu", ivlen, ctx->ivlen);
			return 0;
		}

		memcpy(ctx->iv, iv, ivlen);
	}

	ctx->encrypt = encrypt;

	/* (re)create the hardware session with the current key/IV */
	if (ctx->hw_ctx != NULL) {
		stm32_cipher_freectx(ctx->hw_ctx);
		ctx->hw_ctx = NULL;
	}

	ctx->hw_ctx = stm32_cipher_newctx(ctx->provctx, ctx->hw_alg_name,
					ctx->mode, ctx->keylen);
	if (ctx->hw_ctx == NULL) {
		PUT_ERROR(pctx, STM32_R_CIPHER_INIT_FAILED,
			"failed to open kernel cipher session");
		return 0;
	}

	if (!stm32_cipher_init(ctx->hw_ctx, ctx->key, ctx->keylen,
				ctx->iv, ctx->ivlen, encrypt)) {
		PUT_ERROR(pctx, STM32_R_CIPHER_INIT_FAILED,
			"cipher init failed");
		return 0;
	}

	return 1;
}

static int cipher_encrypt_init(void *vctx, const unsigned char *key, size_t keylen,
			const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[])
{
	return cipher_init((STM32_CIPHER_CTX_ *)vctx, key, keylen, iv, ivlen, 1, params);
}

static int cipher_decrypt_init(void *vctx, const unsigned char *key, size_t keylen,
			const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[])
{
	return cipher_init((STM32_CIPHER_CTX_ *)vctx, key, keylen, iv, ivlen, 0, params);
}

/*********************************************************************
 *
 * Cipher parametres :
 * size key/IV/bloc per algo, padding adjustable
 *****/
static int cipher_get_params(OSSL_PARAM params[], STM32_CIPHER_MODE mode,
				size_t keylen, size_t ivlen, size_t block_size)
{
	OSSL_PARAM *p;
	unsigned int m;
	
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, keylen))
		return 0;
	
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, ivlen))
		return 0;
	
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, block_size))
		return 0;
	
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
	if (p != NULL) {
		switch (mode) {
			/* fix temp :
			 *
			 * /local/home/tabkioum/openssl/providers/implementations/ciphers/ciphercommon.c
			 *
			 * Macro in : /local/home/tabkioum/openssl/include/openssl/evp.h
			 * a temporary fix of the cipher mode (EVP_CIPH_*) 
			 * used in cipher_get_params() to set the mode in OSSL_PARAM
			 */
			case STM32_CIPHER_MODE_ECB : 
				m = EVP_CIPH_ECB_MODE; 
				break;

			case STM32_CIPHER_MODE_CBC : 
				m = EVP_CIPH_CBC_MODE; 
				break;

			case STM32_CIPHER_MODE_CTR : 
				m = EVP_CIPH_CTR_MODE; 
				break;

			default : 
				m = 0; break;
		}
		if (!OSSL_PARAM_set_uint(p, m))
			return 0;
	}
	return 1;
}

static const OSSL_PARAM cipher_gettable_params_list[] = 
{
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
	OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
	OSSL_PARAM_END
};

static const OSSL_PARAM *cipher_gettable_params(void *provctx)
{
	(void)provctx;
	return cipher_gettable_params_list;
}

static const OSSL_PARAM cipher_gettable_ctx_params_list[] = 
{
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
	OSSL_PARAM_int(OSSL_CIPHER_PARAM_PADDING, NULL),
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
	OSSL_PARAM_END
};

static const OSSL_PARAM *cipher_gettable_ctx_params(void *vctx, void *provctx)
{
	(void)vctx;
	(void)provctx;
	return cipher_gettable_ctx_params_list;
}

static int cipher_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
	STM32_CIPHER_CTX_ *ctx = (STM32_CIPHER_CTX_ *)vctx;
	OSSL_PARAM *p;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->ivlen))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->block_size))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
	if (p != NULL && !OSSL_PARAM_set_int(p, ctx->pad_enabled))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
	if (p != NULL && !OSSL_PARAM_set_octet_string(p, ctx->iv, ctx->ivlen))
		return 0;

	return 1;
}

static const OSSL_PARAM cipher_settable_ctx_params_list[] = 
{
	OSSL_PARAM_int(OSSL_CIPHER_PARAM_PADDING, NULL),
	OSSL_PARAM_END
};

static const OSSL_PARAM *cipher_settable_ctx_params(void *vctx, void *provctx)
{
	(void)vctx;
	(void)provctx;
	return cipher_settable_ctx_params_list;
}
/*
* OSSL_CIPHER_PARAM_PADDING
* == EVP_CIPHER_CTX_set_padding(ctx, 0/1)
*/

static int cipher_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
	STM32_CIPHER_CTX_ *ctx = (STM32_CIPHER_CTX_ *)vctx;
	const OSSL_PARAM *p;
	int pad;

	p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
	if (p != NULL) {

		if (!OSSL_PARAM_get_int(p, &pad))
			return 0;

		/* CTR ignore */
		if (ctx->mode != STM32_CIPHER_MODE_CTR)
			ctx->pad_enabled = (pad != 0);
	}
	return 1;
}

/*********************************************************************
*
* Macro defintion per algorithme : AES-{128,192,256}-{ECB,CBC,CTR}
*
*****/
#define DEFINE_CIPHER(name, mode, keybits, keylen, ivlen, blocksize, hwname) 		\
											\
	static void *name##_newctx(void *provctx) 					\
	{ 										\
		return cipher_newctx(provctx, mode, keylen, ivlen, blocksize, hwname);	\
	} 										\
											\
	static int name##_get_params(OSSL_PARAM params[]) 				\
	{ 										\
		return cipher_get_params(params, mode, keylen, ivlen, blocksize); 	\
	} 										\
											\
	static const OSSL_DISPATCH name##_functions[] = { 				\
		{ OSSL_FUNC_CIPHER_NEWCTX,						\
			(void (*)(void))name##_newctx },             			\
		{ OSSL_FUNC_CIPHER_FREECTX, 						\
			(void (*)(void))cipher_freectx },           			\
		{ OSSL_FUNC_CIPHER_ENCRYPT_INIT, 					\
			(void (*)(void))cipher_encrypt_init }, 				\
		{ OSSL_FUNC_CIPHER_DECRYPT_INIT, 					\
			(void (*)(void))cipher_decrypt_init }, 				\
		{ OSSL_FUNC_CIPHER_GET_PARAMS, 						\
			(void (*)(void))name##_get_params }, 				\
		{ OSSL_FUNC_CIPHER_GETTABLE_PARAMS, 					\
			(void (*)(void))cipher_gettable_params },			\
		{ OSSL_FUNC_CIPHER_GET_CTX_PARAMS, 					\
			(void (*)(void))cipher_get_ctx_params }, 			\
		{ OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,	 				\
			(void (*)(void))cipher_gettable_ctx_params }, 			\
		{ OSSL_FUNC_CIPHER_SET_CTX_PARAMS, 					\
			(void (*)(void))cipher_set_ctx_params }, 			\
		{ OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, 				\
			(void (*)(void))cipher_settable_ctx_params }, 			\
		{ 0, NULL } 								\
	}

/* Define the cipher functions for each algorithm supported */
/* AES-ECB (ivlen=0) */
DEFINE_CIPHER(aes128ecb, STM32_CIPHER_MODE_ECB, 128, 16, 0, 16, "stm32-ecb-aes");
DEFINE_CIPHER(aes192ecb, STM32_CIPHER_MODE_ECB, 192, 24, 0, 16, "stm32-ecb-aes");
DEFINE_CIPHER(aes256ecb, STM32_CIPHER_MODE_ECB, 256, 32, 0, 16, "stm32-ecb-aes");
/* AES-CBC : IV 16 bytes */
DEFINE_CIPHER(aes128cbc, STM32_CIPHER_MODE_CBC, 128, 16, 16, 16, "stm32-cbc-aes");
DEFINE_CIPHER(aes192cbc, STM32_CIPHER_MODE_CBC, 192, 24, 16, 16, "stm32-cbc-aes");
DEFINE_CIPHER(aes256cbc, STM32_CIPHER_MODE_CBC, 256, 32, 16, 16, "stm32-cbc-aes");
/* AES-CTR : IV/nonce 16 bytes, block_size = 1 (stream) */
DEFINE_CIPHER(aes128ctr, STM32_CIPHER_MODE_CTR, 128, 16, 16, 1, "stm32-ctr-aes");
DEFINE_CIPHER(aes192ctr, STM32_CIPHER_MODE_CTR, 192, 24, 16, 1, "stm32-ctr-aes");
DEFINE_CIPHER(aes256ctr, STM32_CIPHER_MODE_CTR, 256, 32, 16, 1, "stm32-ctr-aes");

/*********************************************************************
 *
 *  Cipher table for each algorithm supported by the provider
 *  exposed to Openssl core
 *
 *****/
const OSSL_ALGORITHM stm32_ciphers[] = {
	{ STM32_NAME_AES_128_ECB, STM32_PROV_PROPS, aes128ecb_functions,
	"STM32 AES-128-ECB" },
	{ STM32_NAME_AES_192_ECB, STM32_PROV_PROPS, aes192ecb_functions,
	"STM32 AES-192-ECB" },
	{ STM32_NAME_AES_256_ECB, STM32_PROV_PROPS, aes256ecb_functions,
	"STM32 AES-256-ECB" },
	{ STM32_NAME_AES_128_CBC, STM32_PROV_PROPS, aes128cbc_functions,
	"STM32 AES-128-CBC" },
	{ STM32_NAME_AES_192_CBC, STM32_PROV_PROPS, aes192cbc_functions,
	"STM32 AES-192-CBC" },
	{ STM32_NAME_AES_256_CBC, STM32_PROV_PROPS, aes256cbc_functions,
	"STM32 AES-256-CBC" },
	{ STM32_NAME_AES_128_CTR, STM32_PROV_PROPS, aes128ctr_functions,
	"STM32 AES-128-CTR" },
	{ STM32_NAME_AES_192_CTR, STM32_PROV_PROPS, aes192ctr_functions,
	"STM32 AES-192-CTR" },
	{ STM32_NAME_AES_256_CTR, STM32_PROV_PROPS, aes256ctr_functions,
	"STM32 AES-256-CTR" },
	{ NULL, NULL, NULL, NULL }
};