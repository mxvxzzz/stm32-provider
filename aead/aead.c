/*
 * aead.c - STM32 provider: EVP_CIPHER implementation for AES-GCM / AES-CCM
 *
 * Note: 
 *   The kernel AEAD implementations (cryptodev / AF_ALG) are one-shot only.
 *   They do not allow streaming the plaintext, only one data-producing
 *   update() call is accepted. A second such call is explicitly rejected 
 *   cause the tag will be different between the two calls (instead of reusing 
 *   the nonce) which would completely break GCM.
 *
 * stmaead:
 *   A test tool that can process large files in chunks, with an auto-incremented 
 *   nonce per chunk. Each chunk is encrypted/authenticated independently with 
 *   its own AEAD tag (like TLS).
 *
 *
 *  EVP flow to use stm32 provider for AEAD (GCM/CCM):
 *
 *   GCM encryption:
 *
 *  	EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)
 *  	EVP_EncryptUpdate(ctx, NULL, &outl, aad, aadlen)   -> AAD
 *  	EVP_EncryptUpdate(ctx, out,  &outl, pt,  ptlen)    -> encryption
 *  	EVP_EncryptFinal_ex(ctx, out + outl, &tmpl)        -> 0 bytes
 *  	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)
 *
 *   CCM encryption (the tag length and message length must be set
 *   BEFORE the AAD):
 *
 *  	EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL)
 *  	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, taglen, NULL)
 *  	EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)
 *  	EVP_EncryptUpdate(ctx, NULL, &outl, NULL, ptlen)   -> length
 *  	EVP_EncryptUpdate(ctx, NULL, &outl, aad, aadlen)   -> AAD
 *  	EVP_EncryptUpdate(ctx, out,  &outl, pt,  ptlen)    -> encryption
 *  	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, taglen, tag)
 *
 *   Decryption: same flow, with EVP_CTRL_AEAD_SET_TAG(taglen, tag) before
 *   the operation. EVP_DecryptFinal_ex() returns <= 0 if the tag is invalid.
 */

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

/*
 * Debug traces: reserved for test results, sent to stderr.
 * Compile with -DSTM32_AEAD_DEBUG to enable them.
 */
#ifdef STM32_AEAD_DEBUG
# include <stdio.h>
# define AEAD_DBG(fmt, ...) \
	fprintf(stderr, "[stm32-aead] " fmt "\n", ##__VA_ARGS__)
#else
# define AEAD_DBG(fmt, ...) ((void)0)
#endif

struct stm32_aead_ctx_st {
	PROV_CTX *provctx;
	STM32_AEAD_HW_CTX *hw_ctx;

	STM32_AEAD_MODE mode;
	const char *hw_alg_name;

	size_t keylen;
	size_t ivlen;

	int encrypt;
	int initialized; /* key + IV poses */
	int key_set;
	int iv_set;
	int hw_ready; 	 /* session backend open */

	int op_done;	 /* operation one-shot done */
	int tag_valid;	 /* encrypt : tag disponible */
	int auth_ok;  	 /* decrypt : tag verify */
	int tag_set;  	 /* decrypt : tag set */

	unsigned char key[MAX_KEY_SIZE];
	unsigned char iv[MAX_IV_SIZE];

	size_t taglen;
	unsigned char   tag[MAX_TAG_SIZE];

	size_t msg_len;  /* CCM : message length */
	int msg_len_set;

	unsigned char  *aad;
	size_t aad_len;
	size_t aad_alloc;
};

typedef struct stm32_aead_ctx_st STM32_AEAD_CTX;

/*********************************************************************

 Prototypes

*****/
static int aad_append(STM32_AEAD_CTX *ctx, const unsigned char *in, size_t inl);
static int aead_taglen_valid(STM32_AEAD_MODE mode, size_t taglen);
static int aead_ivlen_valid(STM32_AEAD_MODE mode, size_t ivlen);
static int aead_build_hw_iv(STM32_AEAD_CTX *ctx, unsigned char * hw_iv, size_t * hw_ivlen);
static int aead_setup_hw(STM32_AEAD_CTX *ctx);

static void *aead_newctx(void *provctx, STM32_AEAD_MODE mode, size_t keylen, size_t ivlen, const char *hw_alg_name);
static void aead_freectx(void *vctx);
static int aead_init(STM32_AEAD_CTX *ctx, const unsigned char *key, size_t keylen,
		     const unsigned char *iv, size_t ivlen, int encrypt, const OSSL_PARAM params[]);
static int aead_encrypt_init(void *vctx, const unsigned char *key, size_t keylen,
			    const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[]);
static int aead_decrypt_init(void *vctx, const unsigned char *key, size_t keylen,
			    const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[]);

static int aead_run(STM32_AEAD_CTX *ctx, unsigned char *out, size_t *outl, size_t outsize,
		    const unsigned char *in, size_t inl);

static int aead_update(void *vctx, unsigned char *out, size_t *outl, size_t outsize, const unsigned char *in, size_t inl);
static int aead_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize);

static int aead_get_params(OSSL_PARAM params[], STM32_AEAD_MODE mode, size_t keylen, size_t ivlen);
static const OSSL_PARAM *aead_gettable_params(void *provctx);
static const OSSL_PARAM *aead_gettable_ctx_params(void *vctx, void *provctx);
static int aead_get_ctx_params(void *vctx, OSSL_PARAM params[]);
static const OSSL_PARAM *aead_settable_ctx_params(void *vctx, void *provctx);
static int aead_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

/*********************************************************************

 Helpers

*****/
static int aad_append(STM32_AEAD_CTX *ctx, const unsigned char *in, size_t inl)
{
	size_t needed;
	size_t new_alloc;
	unsigned char *tmp;

	/* Software limit on AAD size */
	if (inl > MAX_AAD_SIZE || ctx->aad_len > MAX_AAD_SIZE - inl)
		return 0;

	needed = ctx->aad_len + inl;
	if (needed > ctx->aad_alloc) {
		new_alloc = needed < 4096 ? 4096 : needed;
		tmp = OPENSSL_realloc(ctx->aad, new_alloc);
		if (tmp == NULL)
			return 0;
		ctx->aad = tmp;
		ctx->aad_alloc = new_alloc;
	}
	memcpy(ctx->aad + ctx->aad_len, in, inl);
	ctx->aad_len = needed;
	return 1;
}

static int aead_taglen_valid(STM32_AEAD_MODE mode, size_t taglen)
{
	if (mode == STM32_AEAD_MODE_GCM) {
		switch (taglen) {
			case 4: case 8: case 12: case 13:
			case 14: case 15: case 16:
				return 1;
			default:
				return 0;
		}
	}
	switch (taglen) {
		case 4: case 6: case 8: case 10:
		case 12: case 14: case 16:
			return 1;
		default:
			return 0;
	}
}

static int aead_ivlen_valid(STM32_AEAD_MODE mode, size_t ivlen)
{
	if (mode == STM32_AEAD_MODE_GCM)
		return ivlen == GCM_IV_SIZE;   /* gcm(aes) : ivsize == 12 */

	return ivlen >= 7 && ivlen <= 13;   /* ccm(aes) : 2 <= L <= 8 */
}

/*
 * Builds the IV expected by the kernel.
 *
 * GCM: the 12-byte nonce as is.
 *
 * CCM: the kernel expects a 16-byte block already formatted (RFC 3610):
 *   iv[0]   = L - 1, with L = 15 - noncelen
 *   iv[1..n]   = nonce
 *   iv[n+1..]  = counter, set to zero
 *    crypto_ccm_check_iv() requires 1 <= iv[0] <= 7.
 *
 */
static int aead_build_hw_iv(STM32_AEAD_CTX *ctx, unsigned char * hw_iv,
			 size_t * hw_ivlen)
{
	if (!aead_ivlen_valid(ctx->mode, ctx->ivlen))
		return 0;

	memset( hw_iv, 0, MAX_IV_SIZE);

	if (ctx->mode == STM32_AEAD_MODE_GCM) {
		memcpy( hw_iv, ctx->iv, ctx->ivlen);
		* hw_ivlen = ctx->ivlen;
		return 1;
	}

	/* Construction IV kernel CCM : [L-1] [nonce] [0...0] = 16 bytes */
	 hw_iv[0] = (unsigned char)(15 - ctx->ivlen - 1);   /* L - 1 */
	memcpy( hw_iv + 1, ctx->iv, ctx->ivlen);
	* hw_ivlen = MAX_IV_SIZE;

	return 1;
}

static int aead_setup_hw(STM32_AEAD_CTX *ctx)
{
	if (ctx->hw_ready)
		return 1;

	if (ctx->hw_ctx == NULL) {
		ctx->hw_ctx = stm32_aead_newctx(ctx->provctx, ctx->hw_alg_name,
						ctx->mode, ctx->keylen);
		if (ctx->hw_ctx == NULL)
			return 0;
	}

	if (!stm32_aead_init(ctx->hw_ctx, ctx->key, ctx->keylen,
			  ctx->taglen, ctx->encrypt))
		return 0;

	ctx->hw_ready = 1;
	return 1;
}

/*********************************************************************

 Setup

*****/
static void *aead_newctx(void *provctx, STM32_AEAD_MODE mode, size_t keylen,
			 size_t ivlen, const char *hw_alg_name)
{
	PROV_CTX *pctx = (PROV_CTX *)provctx;
	STM32_AEAD_CTX *ctx;

	if (pctx == NULL)
		return NULL;

	ctx = OPENSSL_zalloc(sizeof(*ctx));
	if (ctx == NULL) {
		PUT_ERROR(pctx, STM32_R_CIPHER_NEWCTX_FAILED,
			  "failed to allocate AEAD context");
		return NULL;
	}

	ctx->provctx  = pctx;
	ctx->mode  = mode;
	ctx->keylen   = keylen;
	ctx->ivlen    = ivlen;
	ctx->hw_alg_name = hw_alg_name;

	ctx->taglen = (mode == STM32_AEAD_MODE_GCM) ? 16 : 12;

	return ctx;
}

static void aead_freectx(void *vctx)
{
	STM32_AEAD_CTX *ctx = (STM32_AEAD_CTX *)vctx;

	if (ctx == NULL)
		return;

	if (ctx->hw_ctx != NULL)
		stm32_aead_freectx(ctx->hw_ctx);

	if (ctx->aad != NULL) {
		OPENSSL_cleanse(ctx->aad, ctx->aad_alloc);
		OPENSSL_free(ctx->aad);
	}

	OPENSSL_cleanse(ctx->key, sizeof(ctx->key));
	OPENSSL_cleanse(ctx->iv, sizeof(ctx->iv));
	OPENSSL_cleanse(ctx->tag, sizeof(ctx->tag));
	OPENSSL_free(ctx);
}

static int aead_init(STM32_AEAD_CTX *ctx,
		  const unsigned char *key, size_t keylen,
		  const unsigned char *iv, size_t ivlen,
		  int encrypt, const OSSL_PARAM params[])
{
	PROV_CTX *pctx;

	if (ctx == NULL)
		return 0;
	pctx = ctx->provctx;

	ctx->encrypt = encrypt;
	ctx->aad_len  = 0;
	ctx->op_done  = 0;
	ctx->tag_valid   = 0;
	ctx->auth_ok  = 0;
	ctx->msg_len_set = 0;
	ctx->hw_ready = 0;

	if (iv != NULL) {
		if (!aead_ivlen_valid(ctx->mode, ivlen)) {
			PUT_ERROR(pctx, STM32_R_INVALID_ARGUMENT,
				  "invalid AEAD IV length: got %zu", ivlen);
			return 0;
		}
		memcpy(ctx->iv, iv, ivlen);
		ctx->ivlen  = ivlen;
		ctx->iv_set = 1;
	}

	if (key != NULL) {
		if (keylen != ctx->keylen) {
			PUT_ERROR(pctx, STM32_R_INVALID_ARGUMENT,
				  "invalid AEAD key length: got %zu expected %zu",
				  keylen, ctx->keylen);
			return 0;
		}
		memcpy(ctx->key, key, keylen);
		ctx->key_set = 1;
	}

	if (params != NULL && !aead_set_ctx_params(ctx, params))
		return 0;

	ctx->initialized = (ctx->key_set && ctx->iv_set);
	return 1;
}

static int aead_encrypt_init(void *vctx, const unsigned char *key, size_t keylen,
			  const unsigned char *iv, size_t ivlen,
			  const OSSL_PARAM params[])
{
	return aead_init((STM32_AEAD_CTX *)vctx, key, keylen, iv, ivlen, 1, params);
}

static int aead_decrypt_init(void *vctx, const unsigned char *key, size_t keylen,
			  const unsigned char *iv, size_t ivlen,
			  const OSSL_PARAM params[])
{
	return aead_init((STM32_AEAD_CTX *)vctx, key, keylen, iv, ivlen, 0, params);
}

/*********************************************************************

 Operation one-shot

*****/
static int aead_run(STM32_AEAD_CTX *ctx, unsigned char *out, size_t *outl,
		 size_t outsize, const unsigned char *in, size_t inl)
{
	PROV_CTX *pctx = ctx->provctx;
	unsigned char hw_iv[MAX_IV_SIZE];
	size_t hw_ivlen = 0;
	size_t written = 0;
	int ret;

	*outl = 0;

	if (!ctx->initialized) {
		PUT_ERROR(pctx, STM32_R_CIPHER_UPDATE_FAILED, "AEAD key or IV not set");
		return 0;
	}

	if (ctx->op_done) {
		PUT_ERROR(pctx, STM32_R_CIPHER_UPDATE_FAILED,
			  "multi-part AEAD update is not supported by the "
			  "hardware backend: pass the whole message in a "
			  "single EVP_%sUpdate() call",
			  ctx->encrypt ? "Encrypt" : "Decrypt");
		return 0;
	}

	if (inl > MAX_ONESHOT_SIZE) {
		PUT_ERROR(pctx, STM32_R_CIPHER_UPDATE_FAILED,
			  "AEAD input too large for a one-shot operation: "
			  "%zu > %d", inl, MAX_ONESHOT_SIZE);
		return 0;
	}

	if (inl > 0 && out != NULL && outsize < inl) {
		PUT_ERROR(pctx, STM32_R_CIPHER_UPDATE_FAILED,
			  "AEAD output buffer too small: %zu < %zu",
			  outsize, inl);
		return 0;
	}

	if (!aead_taglen_valid(ctx->mode, ctx->taglen)) {
		PUT_ERROR(pctx, STM32_R_CIPHER_UPDATE_FAILED,
			  "unsupported AEAD tag length: %zu", ctx->taglen);
		return 0;
	}

	if (ctx->mode == STM32_AEAD_MODE_CCM && ctx->msg_len_set
	 && ctx->msg_len != inl) {
		PUT_ERROR(pctx, STM32_R_CIPHER_UPDATE_FAILED,
			  "CCM message length mismatch: announced %zu got %zu",
			  ctx->msg_len, inl);
		return 0;
	}

	if (!aead_build_hw_iv(ctx, hw_iv, &hw_ivlen)) {
		PUT_ERROR(pctx, STM32_R_CIPHER_UPDATE_FAILED,
			  "cannot build hardware IV (ivlen=%zu)", ctx->ivlen);
		return 0;
	}

	if (!aead_setup_hw(ctx))
		return 0;

	ctx->op_done = 1;

	if (ctx->encrypt) {
		ret = stm32_aead_encrypt(ctx->hw_ctx, hw_iv, hw_ivlen,
					 ctx->aad, ctx->aad_len, in, inl,
					 out, &written, ctx->tag, ctx->taglen);
		if (ret != STM32_AEAD_OK) {
			PUT_ERROR(pctx, STM32_R_CIPHER_UPDATE_FAILED, "AEAD hardware encrypt failed");
			return 0;
		}
		ctx->tag_valid = 1;
	} else {
		if (!ctx->tag_set) {
			PUT_ERROR(pctx, STM32_R_CIPHER_UPDATE_FAILED,
				  "AEAD tag not set before decryption");
			return 0;
		}
		ret = stm32_aead_decrypt(ctx->hw_ctx, hw_iv, hw_ivlen,
					 ctx->aad, ctx->aad_len, in, inl,
					 out, &written, ctx->tag, ctx->taglen);
		if (ret == STM32_AEAD_AUTH_FAIL) {
			/* No return unauthenticated plaintext. */
			if (out != NULL && inl > 0)
				OPENSSL_cleanse(out, inl);

			PUT_ERROR(pctx, STM32_R_CIPHER_UPDATE_FAILED, "AEAD authentication failure");
			return 0;
		}
		if (ret != STM32_AEAD_OK) {
			PUT_ERROR(pctx, STM32_R_CIPHER_UPDATE_FAILED, "AEAD hardware decrypt failed");
			return 0;
		}
		ctx->auth_ok = 1;
	}

	if (written != inl) {
		PUT_ERROR(pctx, STM32_R_CIPHER_UPDATE_FAILED,
			  "AEAD backend produced %zu bytes, expected %zu",
			  written, inl);
		return 0;
	}

	*outl = written;
	AEAD_DBG("op done: enc=%d aad=%zu len=%zu tag=%zu",
		 ctx->encrypt, ctx->aad_len, inl, ctx->taglen);
	return 1;
}

/*********************************************************************

 Update/ Final

*****/
static int aead_update(void *vctx, unsigned char *out, size_t *outl,
		    size_t outsize, const unsigned char *in, size_t inl)
{
	STM32_AEAD_CTX *ctx = (STM32_AEAD_CTX *)vctx;

	if (ctx == NULL || outl == NULL)
		return 0;

	*outl = 0;

	if (!ctx->initialized) {
		PUT_ERROR(ctx->provctx, STM32_R_CIPHER_UPDATE_FAILED,
			  "AEAD not initialized (missing key or IV)");
		return 0;
	}

	/* CCM : update(out=NULL, in=NULL, inl=len) */
	if (out == NULL && in == NULL) {
		ctx->msg_len  = inl;
		ctx->msg_len_set = 1;
		*outl = inl;
		return 1;
	}

	/* AAD : update(out=NULL, in=aad). */
	if (out == NULL) {
		if (inl == 0)
			return 1;
		if (ctx->op_done) {
			PUT_ERROR(ctx->provctx, STM32_R_CIPHER_UPDATE_FAILED,
				  "AAD supplied after the AEAD operation");
			return 0;
		}
		if (!aad_append(ctx, in, inl)) {
			PUT_ERROR(ctx->provctx, STM32_R_CIPHER_UPDATE_FAILED,
				  "failed to buffer AAD (len=%zu, max=%d)",
				  inl, MAX_AAD_SIZE);
			return 0;
		}
		*outl = inl;
		return 1;
	}

	/* data : operation done. */
	if (inl == 0)
		return 1;

	return aead_run(ctx, out, outl, outsize, in, inl);
}

static int aead_final(void *vctx, unsigned char *out, size_t *outl,
		   size_t outsize)
{
	STM32_AEAD_CTX *ctx = (STM32_AEAD_CTX *)vctx;
	size_t dummy = 0;

	(void)out;
	(void)outsize;

	if (ctx == NULL || outl == NULL)
		return 0;

	*outl = 0;

	if (!ctx->initialized) {
		PUT_ERROR(ctx->provctx, STM32_R_CIPHER_FINAL_FAILED,
			  "AEAD not initialized");
		return 0;
	}

	/*
	 * Empty message (AAD only) : the operation has not yet occurred,
	 * EVP passes outsize == 0 for a block cipher, so no data can exit here.
	 */
	if (!ctx->op_done) {
		if (!aead_run(ctx, NULL, &dummy, 0, NULL, 0))
			return 0;
	}

	if (!ctx->encrypt && !ctx->auth_ok) {
		PUT_ERROR(ctx->provctx, STM32_R_CIPHER_FINAL_FAILED,
			  "AEAD authentication failure");
		return 0;
	}

	return 1;
}

/*********************************************************************

 Parametres

*****/
static int aead_get_params(OSSL_PARAM params[], STM32_AEAD_MODE mode,
			   size_t keylen, size_t ivlen)
{
	OSSL_PARAM *p;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, keylen))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, ivlen))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, 1))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
	if (p != NULL
	 && !OSSL_PARAM_set_uint(p, mode == STM32_AEAD_MODE_GCM
					? EVP_CIPH_GCM_MODE : EVP_CIPH_CCM_MODE))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
	if (p != NULL && !OSSL_PARAM_set_int(p, 1))
		return 0;

	/* AEAD => IV handled by the implementation (EVP_CIPH_CUSTOM_IV) */
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
	if (p != NULL && !OSSL_PARAM_set_int(p, 1))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS);
	if (p != NULL && !OSSL_PARAM_set_int(p, 0))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK);
	if (p != NULL && !OSSL_PARAM_set_int(p, 0))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY);
	if (p != NULL && !OSSL_PARAM_set_int(p, 0))
		return 0;

	return 1;
}

static const OSSL_PARAM aead_gettable_params_list[] = {
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
	OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
	OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
	OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
	OSSL_PARAM_int(OSSL_CIPHER_PARAM_CTS, NULL),
	OSSL_PARAM_int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, NULL),
	OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
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
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
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
	OSSL_PARAM *p;

	if (ctx == NULL)
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->ivlen))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->taglen))
		return 0;

	/* EVP_CTRL_AEAD_GET_TAG */
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
	if (p != NULL) {
		if (p->data_type != OSSL_PARAM_OCTET_STRING) {
			PUT_ERROR(ctx->provctx, STM32_R_INVALID_ARGUMENT,
				  "AEAD tag parameter must be an octet string");
			return 0;
		}
		if (!ctx->encrypt || !ctx->tag_valid) {
			PUT_ERROR(ctx->provctx, STM32_R_INVALID_ARGUMENT,
				  "AEAD tag is not available yet");
			return 0;
		}
		if (p->data == NULL || p->data_size == 0
		 || p->data_size > ctx->taglen) {
			PUT_ERROR(ctx->provctx, STM32_R_INVALID_ARGUMENT,
				  "invalid AEAD tag buffer size: %zu",
				  p->data_size);
			return 0;
		}
		memcpy(p->data, ctx->tag, p->data_size);
		p->return_size = p->data_size;
	}

	return 1;
}

static const OSSL_PARAM aead_settable_ctx_params_list[] = {
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
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
	size_t sz;

	if (ctx == NULL)
		return 0;

	if (params == NULL)
		return 1;

	/*
	 * EVP_CTRL_AEAD_SET_TAG :
	 *   - data == NULL : only sets the tag length (CCM encryption)
	 *   - data != NULL : provides the tag to be verified (decryption)
	 */
	p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
	if (p != NULL) {
		if (p->data_type != OSSL_PARAM_OCTET_STRING) {
			PUT_ERROR(ctx->provctx, STM32_R_INVALID_ARGUMENT,
				  "AEAD tag parameter must be an octet string");
			return 0;
		}
		if (!aead_taglen_valid(ctx->mode, p->data_size)) {
			PUT_ERROR(ctx->provctx, STM32_R_INVALID_ARGUMENT,
				  "unsupported AEAD tag length: %zu",
				  p->data_size);
			return 0;
		}
		if (p->data != NULL) {
			if (ctx->encrypt) {
				PUT_ERROR(ctx->provctx, STM32_R_INVALID_ARGUMENT,
					  "cannot set an AEAD tag when encrypting");
				return 0;
			}
			memcpy(ctx->tag, p->data, p->data_size);
			ctx->tag_set = 1;
		}
		if (ctx->taglen != p->data_size) {
			ctx->taglen   = p->data_size;
			ctx->hw_ready = 0;   /* set on the backend side */
		}
	}

	p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
	if (p != NULL) {
		size_t new_ivlen;
		if (!OSSL_PARAM_get_size_t(p, &new_ivlen))
			return 0;
		/* CCM nonce : 7-13 bytes */
		if (ctx->mode == STM32_AEAD_MODE_CCM) {
			if (new_ivlen < 7 || new_ivlen > 13)
			return 0;
		}
		ctx->ivlen = new_ivlen;
	}

	p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
	if (p != NULL) {
		if (!OSSL_PARAM_get_size_t(p, &sz))
			return 0;
		if (!aead_taglen_valid(ctx->mode, sz)) {
			PUT_ERROR(ctx->provctx, STM32_R_INVALID_ARGUMENT,
				  "unsupported AEAD tag length: %zu", sz);
			return 0;
		}
		if (ctx->taglen != sz) {
			ctx->taglen   = sz;
			ctx->hw_ready = 0;
		}
	}

	/* EVP_CTRL_AEAD_SET_IVLEN */
	p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
	if (p != NULL) {
		if (!OSSL_PARAM_get_size_t(p, &sz))
			return 0;
		if (!aead_ivlen_valid(ctx->mode, sz)) {
			PUT_ERROR(ctx->provctx, STM32_R_INVALID_ARGUMENT,
				  "unsupported AEAD IV length: %zu "
				  "(gcm(aes) requires 12, ccm(aes) 7..13)", sz);
			return 0;
		}
		ctx->ivlen = sz;
	}

	p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
	if (p != NULL) {
		if (!OSSL_PARAM_get_size_t(p, &sz))
			return 0;
		if (sz != ctx->keylen) {
			PUT_ERROR(ctx->provctx, STM32_R_INVALID_ARGUMENT,
				  "invalid AEAD key length: got %zu expected %zu",
				  sz, ctx->keylen);
			return 0;
		}
	}

	return 1;
}

/*********************************************************************

  Dispatch table

*****/
#define DEFINE_AEAD(name, mode, keylen, ivlen, hwname)							\
	static void *name##_newctx(void *provctx)							\
	{												\
		return aead_newctx(provctx, mode, keylen, ivlen, hwname);				\
	}												\
													\
	static int name##_get_params(OSSL_PARAM params[])						\
	{												\
		return aead_get_params(params, mode, keylen, ivlen);					\
	}												\
													\
	static const OSSL_DISPATCH name##_functions[] = {						\
		{ OSSL_FUNC_CIPHER_NEWCTX,		(void (*)(void))name##_newctx },		\
		{ OSSL_FUNC_CIPHER_FREECTX,		(void (*)(void))aead_freectx },			\
		{ OSSL_FUNC_CIPHER_ENCRYPT_INIT,	(void (*)(void))aead_encrypt_init },		\
		{ OSSL_FUNC_CIPHER_DECRYPT_INIT,	(void (*)(void))aead_decrypt_init },		\
		{ OSSL_FUNC_CIPHER_UPDATE,		(void (*)(void))aead_update },			\
		{ OSSL_FUNC_CIPHER_FINAL,		(void (*)(void))aead_final },			\
		{ OSSL_FUNC_CIPHER_GET_PARAMS,		(void (*)(void))name##_get_params },		\
		{ OSSL_FUNC_CIPHER_GETTABLE_PARAMS,	(void (*)(void))aead_gettable_params },		\
		{ OSSL_FUNC_CIPHER_GET_CTX_PARAMS,	(void (*)(void))aead_get_ctx_params },		\
		{ OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,	(void (*)(void))aead_gettable_ctx_params }, 	\
		{ OSSL_FUNC_CIPHER_SET_CTX_PARAMS,	(void (*)(void))aead_set_ctx_params },		\
		{ OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,	(void (*)(void))aead_settable_ctx_params }, 	\
		{ 0, NULL }										\
	}

DEFINE_AEAD(aes128gcm, STM32_AEAD_MODE_GCM, 16, GCM_IV_SIZE, "gcm(aes)");
DEFINE_AEAD(aes192gcm, STM32_AEAD_MODE_GCM, 24, GCM_IV_SIZE, "gcm(aes)");
DEFINE_AEAD(aes256gcm, STM32_AEAD_MODE_GCM, 32, GCM_IV_SIZE, "gcm(aes)");

DEFINE_AEAD(aes128ccm, STM32_AEAD_MODE_CCM, 16, CCM_IV_DEFAULT, "ccm(aes)");
DEFINE_AEAD(aes192ccm, STM32_AEAD_MODE_CCM, 24, CCM_IV_DEFAULT, "ccm(aes)");
DEFINE_AEAD(aes256ccm, STM32_AEAD_MODE_CCM, 32, CCM_IV_DEFAULT, "ccm(aes)");

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