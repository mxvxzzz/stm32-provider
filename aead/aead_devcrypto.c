#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>

#include <openssl/core.h>
#include <openssl/crypto.h>

#include "aead.h"
#include "../include/prov.h"
#include "../include/err.h"

struct stm32_aead_hw_ctx_st {
	PROV_CTX *provctx;
	int cfd;
	struct session_op sess;
	int session_open;
	STM32_AEAD_MODE mode;
	size_t keylen;
	size_t taglen;
	int encrypt;
	unsigned char key[MAX_KEY_SIZE];
};

static unsigned int aead_cipher_id(STM32_AEAD_MODE mode)
{
	switch (mode) {
	case STM32_AEAD_MODE_GCM:
		return CRYPTO_AES_GCM;
	case STM32_AEAD_MODE_CCM:
		return CRYPTO_AES_CCM;
	default:
		return 0;
	}
}

STM32_AEAD_HW_CTX *stm32_aead_newctx(void *vprovctx, const char *alg_name,
				 STM32_AEAD_MODE mode, size_t keylen)
{
	PROV_CTX *pctx = (PROV_CTX *)vprovctx;
	STM32_AEAD_HW_CTX *ctx;

	(void)alg_name;

	if (pctx == NULL || keylen == 0 || keylen > MAX_KEY_SIZE)
		return NULL;
	if (aead_cipher_id(mode) == 0)
		return NULL;

	ctx = OPENSSL_zalloc(sizeof(*ctx));
	if (ctx == NULL) {
		PUT_ERROR(pctx, STM32_R_CIPHER_NEWCTX_FAILED,
			 "failed to allocate cryptodev AEAD context");
		return NULL;
	}

	ctx->provctx = pctx;
	ctx->cfd = -1;
	ctx->mode = mode;
	ctx->keylen = keylen;

	ctx->cfd = open("/dev/crypto", O_RDWR, 0);
	if (ctx->cfd < 0) {
		PUT_ERROR_ERRNO(pctx, STM32_R_CIPHER_NEWCTX_FAILED,
				"open /dev/crypto");
		OPENSSL_free(ctx);
		return NULL;
	}
	return ctx;
}

void stm32_aead_freectx(STM32_AEAD_HW_CTX *ctx)
{
	if (ctx == NULL)
		return;
	if (ctx->cfd >= 0) {
		if (ctx->session_open)
			ioctl(ctx->cfd, CIOCFSESSION, &ctx->sess.ses);
		close(ctx->cfd);
	}
	OPENSSL_cleanse(ctx->key, sizeof(ctx->key));
	OPENSSL_free(ctx);
}

int stm32_aead_init(STM32_AEAD_HW_CTX *ctx, const unsigned char *key,
		 size_t keylen, size_t taglen, int encrypt)
{
	if (ctx == NULL || ctx->cfd < 0 || key == NULL)
		return 0;
	if (keylen == 0 || keylen > MAX_KEY_SIZE || taglen > MAX_TAG_SIZE)
		return 0;

	if (ctx->session_open) {
		ioctl(ctx->cfd, CIOCFSESSION, &ctx->sess.ses);
		ctx->session_open = 0;
	}

	memcpy(ctx->key, key, keylen);
	ctx->keylen = keylen;
	ctx->taglen = taglen;
	ctx->encrypt = encrypt;

	memset(&ctx->sess, 0, sizeof(ctx->sess));
	ctx->sess.cipher = aead_cipher_id(ctx->mode);
	ctx->sess.keylen = (uint32_t)keylen;
	ctx->sess.key = ctx->key;

	if (ioctl(ctx->cfd, CIOCGSESSION, &ctx->sess) < 0) {
		PUT_ERROR_ERRNO(ctx->provctx, STM32_R_CIPHER_INIT_FAILED,
				"cryptodev CIOCGSESSION");
		return 0;
	}

	ctx->session_open = 1;
	return 1;
}

int stm32_aead_encrypt(STM32_AEAD_HW_CTX *ctx, const unsigned char *iv, size_t ivlen,
		const unsigned char *aad, size_t aadlen, const unsigned char *in, size_t inl,
		unsigned char *out, size_t *outl, unsigned char *tag, size_t taglen)
{
	struct crypt_auth_op cao;
	unsigned char *dst_buf;
	int rv = STM32_AEAD_ERROR;

	if (ctx == NULL || !ctx->session_open || outl == NULL)
		return STM32_AEAD_ERROR;

	if (iv == NULL || ivlen == 0 || ivlen > MAX_IV_SIZE)
		return STM32_AEAD_ERROR;

	if (taglen == 0 || taglen > MAX_TAG_SIZE || tag == NULL)
		return STM32_AEAD_ERROR;

	if (aadlen > 0 && aad == NULL)
		return STM32_AEAD_ERROR;

	if (inl > 0 && (in == NULL || out == NULL))
		return STM32_AEAD_ERROR;

	*outl = 0;

	/* dst must contain ciphertext || tag (cryptodev_get_dst_len) */
	dst_buf = OPENSSL_zalloc(inl + taglen);
	if (dst_buf == NULL)
		return STM32_AEAD_ERROR;

	memset(&cao, 0, sizeof(cao));
	cao.ses = ctx->sess.ses;
	cao.op = COP_ENCRYPT;
	cao.flags = 0;
	cao.len = (uint32_t)inl;
	cao.auth_len = (uint32_t)aadlen;
	cao.auth_src = (unsigned char *)(uintptr_t)aad;
	cao.src = (unsigned char *)(uintptr_t)in;
	cao.dst = dst_buf;
	cao.iv = (unsigned char *)(uintptr_t)iv;
	cao.iv_len = (uint32_t)ivlen;
	cao.tag_len = (uint32_t)taglen;

	if (ioctl(ctx->cfd, CIOCAUTHCRYPT, &cao) < 0) {
		PUT_ERROR_ERRNO(ctx->provctx, STM32_R_CIPHER_UPDATE_FAILED,
				"cryptodev CIOCAUTHCRYPT (encrypt)");
		goto out;
	}

	if (cao.len != inl + taglen) {
		PUT_ERROR(ctx->provctx, STM32_R_CIPHER_UPDATE_FAILED,
			 "cryptodev returned %u bytes, expected %zu",
			 (unsigned int)cao.len, inl + taglen);
		goto out;
	}

	if (inl > 0)
		memcpy(out, dst_buf, inl);
	memcpy(tag, dst_buf + inl, taglen);
	*outl = inl;
	rv = STM32_AEAD_OK;

out:
	OPENSSL_cleanse(dst_buf, inl + taglen);
	OPENSSL_free(dst_buf);
	return rv;
}

int stm32_aead_decrypt(STM32_AEAD_HW_CTX *ctx,
		 const unsigned char *iv, size_t ivlen,
		 const unsigned char *aad, size_t aadlen,
		 const unsigned char *in, size_t inl,
		 unsigned char *out, size_t *outl,
		 const unsigned char *tag, size_t taglen)
{
	struct crypt_auth_op cao;
	unsigned char *buf;
	size_t buf_len;
	int rv = STM32_AEAD_ERROR;

	if (ctx == NULL || !ctx->session_open || outl == NULL)
		return STM32_AEAD_ERROR;
	if (iv == NULL || ivlen == 0 || ivlen > MAX_IV_SIZE)
		return STM32_AEAD_ERROR;
	if (taglen == 0 || taglen > MAX_TAG_SIZE || tag == NULL)
		return STM32_AEAD_ERROR;
	if (aadlen > 0 && aad == NULL)
		return STM32_AEAD_ERROR;
	if (inl > 0 && (in == NULL || out == NULL))
		return STM32_AEAD_ERROR;

	*outl = 0;

	/* src = encrypt || tag, operation en place */
	buf_len = inl + taglen;
	buf = OPENSSL_malloc(buf_len);
	if (buf == NULL)
		return STM32_AEAD_ERROR;

	if (inl > 0)
		memcpy(buf, in, inl);
	memcpy(buf + inl, tag, taglen);

	memset(&cao, 0, sizeof(cao));
	cao.ses = ctx->sess.ses;
	cao.op = COP_DECRYPT;
	cao.flags = 0;
	cao.len = (uint32_t)buf_len;
	cao.auth_len = (uint32_t)aadlen;
	cao.auth_src = (unsigned char *)(uintptr_t)aad;
	cao.src = buf;
	cao.dst = buf;
	cao.iv = (unsigned char *)(uintptr_t)iv;
	cao.iv_len = (uint32_t)ivlen;
	cao.tag_len = (uint32_t)taglen;

	if (ioctl(ctx->cfd, CIOCAUTHCRYPT, &cao) < 0) {
		if (errno == EBADMSG || errno == EINVAL) {
			/* mismatch between "invalid tag" and "invalid parameter": 
			 * EBADMSG is returned from crypto_aead in case 
			 * of authentication failure.
			 */
			if (errno == EBADMSG) {
				rv = STM32_AEAD_AUTH_FAIL;
				goto out;
			}
		}
		PUT_ERROR_ERRNO(ctx->provctx, STM32_R_CIPHER_UPDATE_FAILED,
				"cryptodev CIOCAUTHCRYPT (decrypt)");
		goto out;
	}

	if (cao.len != inl) {
		PUT_ERROR(ctx->provctx, STM32_R_CIPHER_UPDATE_FAILED,
			 "cryptodev returned %u bytes, expected %zu",
			 (unsigned int)cao.len, inl);
		goto out;
	}

	if (inl > 0)
		memcpy(out, buf, inl);

	*outl = inl;
	rv = STM32_AEAD_OK;

out:
	OPENSSL_cleanse(buf, buf_len);
	OPENSSL_free(buf);
	return rv;
}