#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "aead.h"
#include "../include/prov.h"
#include "../include/names.h"
#include "../include/err.h"

struct stm32_aead_ctx_st {
	void *provctx;
	STM32_AEAD_HW_CTX *hw_ctx;
	STM32_AEAD_MODE mode;
	size_t keylen;
	size_t ivlen;
	const char *hw_alg_name;
	int encrypt;
	int initialized;
	int iv_set;
	int key_set;
	int tag_set;
	unsigned char key[32];
	unsigned char iv[16];
	size_t taglen;
	unsigned char tag[MAX_TAG_SIZE];
};

typedef struct stm32_aead_ctx_st STM32_AEAD_CTX;


static void *aead_newctx(void *provctx, STM32_AEAD_MODE mode,
size_t keylen, size_t ivlen, const char *hw_alg_name)
{
	PROV_CTX*pctx = (PROV_CTX *)provctx;
	STM32_AEAD_CTX *ctx;
	if (pctx == NULL)
		return NULL;

	ctx = OPENSSL_zalloc(sizeof(*ctx));
	if (ctx == NULL) {
		PUT_ERROR(pctx, STM32_R_CIPHER_NEWCTX_FAILED,
		"failed to allocate AEAD context");
		return NULL;
	}

	ctx->provctx= provctx;
	ctx->hw_ctx = NULL;
	ctx->mode   = mode;
	ctx->keylen = keylen;
	ctx->ivlen  = ivlen;
	ctx->hw_alg_name = hw_alg_name;
	ctx->taglen = MAX_TAG_SIZE; 
	ctx->initialized = 0;
	return ctx;
}

static void aead_freectx(void *vctx)
{
	STM32_AEAD_CTX *ctx = (STM32_AEAD_CTX *)vctx;
	if (ctx == NULL)
		return;

	if (ctx->hw_ctx)
		stm32_aead_freectx(ctx->hw_ctx);

	OPENSSL_cleanse(ctx->key, sizeof(ctx->key));
	OPENSSL_cleanse(ctx->iv,  sizeof(ctx->iv));
	OPENSSL_cleanse(ctx->tag, sizeof(ctx->tag));
	OPENSSL_free(ctx);
}

/*********************************************************************

 Init

*****/
static int aead_init(STM32_AEAD_CTX *ctx, const unsigned char *key, size_t keylen,
			const unsigned char *iv, size_t ivlen, int encrypt, const OSSL_PARAM params[])
{
	PROV_CTX *pctx = (PROV_CTX *)ctx->provctx;
	return 0;
}

static int aead_encrypt_init(void *vctx, const unsigned char *key, size_t keylen, 
			const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[])
{
	return aead_init((STM32_AEAD_CTX *)vctx, key, keylen, iv, ivlen, 1, params);
}

static int aead_decrypt_init(void *vctx, const unsigned char *key, size_t keylen, 
				const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[])
{
	return aead_init((STM32_AEAD_CTX *)vctx, key, keylen, iv, ivlen, 0, params);
}

/*********************************************************************

 Parametres

*****/
static int aead_get_params(OSSL_PARAM params[], STM32_AEAD_MODE mode, size_t keylen, size_t ivlen)
{
	OSSL_PARAM  *p;
	unsigned int m;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, keylen))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, ivlen))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, 1))   /* stream-like */
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
	if (p != NULL) {
		m = (mode == STM32_AEAD_MODE_GCM) ? EVP_CIPH_GCM_MODE : EVP_CIPH_CCM_MODE;
		if (!OSSL_PARAM_set_uint(p, m))
			return 0;
	}

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
	if (p != NULL && !OSSL_PARAM_set_int(p, 1))
		return 0;

	return 1;
}

static const OSSL_PARAM aead_gettable_params_list[] = {
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
	OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
	OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
	OSSL_PARAM_END
};

static const OSSL_PARAM *aead_gettable_params(void *provctx)
{
	(void)provctx;
	return aead_gettable_params_list;
}

static const OSSL_PARAM aead_gettable_ctx_params_list[] = {
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
	OSSL_PARAM_END
};

static const OSSL_PARAM *aead_gettable_ctx_params(void *vctx, void *provctx)
{
	(void)vctx;
	(void)provctx;
	return aead_gettable_ctx_params_list;
}

static int aead_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
	STM32_AEAD_CTX *ctx = (STM32_AEAD_CTX *)vctx;
	OSSL_PARAM*p;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->ivlen))
		return 0;

	/* retrieve the tag after encryption */
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
	if (p != NULL) {
		if (!ctx->encrypt || ctx->taglen == 0)
			return 0;
		if (!OSSL_PARAM_set_octet_string(p, ctx->tag, ctx->taglen))
			return 0;
	}

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->taglen))
		return 0;

	return 1;
}

static const OSSL_PARAM aead_settable_ctx_params_list[] = {
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
	//OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_IV_GENERATED, NULL, 0),
	OSSL_PARAM_END
};

static const OSSL_PARAM *aead_settable_ctx_params(void *vctx, void *provctx)
{
	(void)vctx;
	(void)provctx;
	return aead_settable_ctx_params_list;
}

static int aead_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
	STM32_AEAD_CTX *ctx = (STM32_AEAD_CTX *)vctx;
	const OSSL_PARAM *p;
	size_t len;
	const void *data;

	p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
	if (p != NULL) {
		if (p->data_size > MAX_TAG_SIZE)
			return 0;
		if (!OSSL_PARAM_get_octet_string_ptr(p, &data, &len))
			return 0;
		memcpy(ctx->tag, data, len);
		ctx->taglen  = len;
		ctx->tag_set = 1;
	}
	p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
	if (p != NULL) {
		if (!OSSL_PARAM_get_size_t(p, &len))
			return 0;
		if (len > MAX_TAG_SIZE)
			return 0;
		ctx->taglen = len;
	}
	return 1;
}


#define DEFINE_AEAD(name, mode, keylen, ivlen, hwname) 							\
	static void *name##_newctx(void *provctx) 							\
	{  												\
		return aead_newctx(provctx, mode, keylen, ivlen, hwname); 				\
	}  												\
	 												\
	static int name##_get_params(OSSL_PARAM params[])   						\
	{  												\
		return aead_get_params(params, mode, keylen, ivlen);  					\
	}  												\
   													\
	static const OSSL_DISPATCH name##_functions[] = {   						\
		{ OSSL_FUNC_CIPHER_NEWCTX,    (void(*)(void))name##_newctx },    			\
		{ OSSL_FUNC_CIPHER_FREECTX,   (void(*)(void))aead_freectx  },    			\
		{ OSSL_FUNC_CIPHER_ENCRYPT_INIT,   (void(*)(void))aead_encrypt_init  }, 		\
		{ OSSL_FUNC_CIPHER_DECRYPT_INIT,   (void(*)(void))aead_decrypt_init  }, 		\
		/*{ OSSL_FUNC_CIPHER_UPDATE,    (void(*)(void))aead_update   },*/ 			\
		/*{ OSSL_FUNC_CIPHER_FINAL,(void(*)(void))aead_final    },*/ 				\
		{ OSSL_FUNC_CIPHER_GET_PARAMS,(void(*)(void))name##_get_params  }, 			\
		{ OSSL_FUNC_CIPHER_GETTABLE_PARAMS,(void(*)(void))aead_gettable_params    }, 		\
		{ OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void(*)(void))aead_get_ctx_params}, 		\
		{ OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void(*)(void))aead_gettable_ctx_params}, 	\
		{ OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void(*)(void))aead_set_ctx_params},			\
		{ OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void(*)(void))aead_settable_ctx_params}, 	\
		{ 0, NULL }   										\
	}

DEFINE_AEAD(aes128gcm, STM32_AEAD_MODE_GCM, 16, GCM_IV_SIZE, "gcm(aes)");
DEFINE_AEAD(aes192gcm, STM32_AEAD_MODE_GCM, 24, GCM_IV_SIZE, "gcm(aes)");
DEFINE_AEAD(aes256gcm, STM32_AEAD_MODE_GCM, 32, GCM_IV_SIZE, "gcm(aes)");

DEFINE_AEAD(aes128ccm, STM32_AEAD_MODE_CCM, 16, CCM_IV_SIZE, "ccm(aes)");
DEFINE_AEAD(aes192ccm, STM32_AEAD_MODE_CCM, 24, CCM_IV_SIZE, "ccm(aes)");
DEFINE_AEAD(aes256ccm, STM32_AEAD_MODE_CCM, 32, CCM_IV_SIZE, "ccm(aes)");


const OSSL_ALGORITHM stm32_aead_ciphers[] = {
	{ STM32_NAME_AES_128_GCM, STM32_PROV_PROPS, aes128gcm_functions,
	"STM32 AES-128-GCM" },
	{ STM32_NAME_AES_192_GCM, STM32_PROV_PROPS, aes192gcm_functions,
	"STM32 AES-192-GCM" },
	{ STM32_NAME_AES_256_GCM, STM32_PROV_PROPS, aes256gcm_functions,
	"STM32 AES-256-GCM" },
	{ STM32_NAME_AES_128_CCM, STM32_PROV_PROPS, aes128ccm_functions,
	"STM32 AES-128-CCM" },
	{ STM32_NAME_AES_192_CCM, STM32_PROV_PROPS, aes192ccm_functions,
	"STM32 AES-192-CCM" },
	{ STM32_NAME_AES_256_CCM, STM32_PROV_PROPS, aes256ccm_functions,
	"STM32 AES-256-CCM" },
	{ NULL, NULL, NULL, NULL }
};
