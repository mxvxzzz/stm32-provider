#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_alg.h>

#include <openssl/core.h>
#include <openssl/crypto.h>

#include "aead.h"
#include "../include/prov.h"
#include "../include/err.h"

#ifndef SOL_ALG
#define SOL_ALG 279
#endif
#ifndef ALG_SET_AEAD_ASSOCLEN
#define ALG_SET_AEAD_ASSOCLEN 4
#endif
#ifndef ALG_SET_AEAD_AUTHSIZE
#define ALG_SET_AEAD_AUTHSIZE 5
#endif

struct stm32_aead_hw_ctx_st {
	PROV_CTX *provctx;
	int tf_fd;
	STM32_AEAD_MODE mode;
	size_t keylen;
	size_t taglen;
	int encrypt;
};

static int afalg_aead_open_tfm(PROV_CTX *pctx, const char *alg_name)
{
	struct sockaddr_alg sa;
	int tf_fd;

	tf_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (tf_fd < 0) {
		PUT_ERROR_ERRNO(pctx, STM32_R_CIPHER_NEWCTX_FAILED,
				"AF_ALG AEAD socket()");
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.salg_family = AF_ALG;
	OPENSSL_strlcpy((char *)sa.salg_type, "aead", sizeof(sa.salg_type));
	OPENSSL_strlcpy((char *)sa.salg_name, alg_name, sizeof(sa.salg_name));

	if (bind(tf_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		/*
		 * ENOENT here = the algorithm does not exist OR
		 * CONFIG_CRYPTO_USER_API_AEAD is not enabled in the kernel.
		 */
		PUT_ERROR_ERRNO(pctx, STM32_R_CIPHER_NEWCTX_FAILED,
				"AF_ALG AEAD bind()");
		close(tf_fd);
		return -1;
	}
	return tf_fd;
}

STM32_AEAD_HW_CTX *stm32_aead_newctx(void *vprovctx, const char *alg_name,
				     STM32_AEAD_MODE mode, size_t keylen)
{
	PROV_CTX *pctx = (PROV_CTX *)vprovctx;
	STM32_AEAD_HW_CTX *ctx;

	if (pctx == NULL || alg_name == NULL || keylen == 0 || keylen > MAX_KEY_SIZE)
		return NULL;

	ctx = OPENSSL_zalloc(sizeof(*ctx));
	if (ctx == NULL) {
		PUT_ERROR(pctx, STM32_R_CIPHER_NEWCTX_FAILED,
			 "failed to allocate AF_ALG AEAD context");
		return NULL;
	}

	ctx->provctx = pctx;
	ctx->tf_fd = -1;
	ctx->mode = mode;
	ctx->keylen = keylen;

	ctx->tf_fd = afalg_aead_open_tfm(pctx, alg_name);
	if (ctx->tf_fd < 0) {
		OPENSSL_free(ctx);
		return NULL;
	}
	return ctx;
}

void stm32_aead_freectx(STM32_AEAD_HW_CTX *ctx)
{
	if (ctx == NULL)
		return;
	if (ctx->tf_fd >= 0)
		close(ctx->tf_fd);
	OPENSSL_free(ctx);
}

int stm32_aead_init(STM32_AEAD_HW_CTX *ctx, const unsigned char *key,
		    size_t keylen, size_t taglen, int encrypt)
{
	if (ctx == NULL || ctx->tf_fd < 0 || key == NULL)
		return 0;
	if (keylen == 0 || keylen > MAX_KEY_SIZE || taglen > MAX_TAG_SIZE)
		return 0;

	ctx->taglen = taglen;
	ctx->encrypt = encrypt;

	if (setsockopt(ctx->tf_fd, SOL_ALG, ALG_SET_KEY,
		 key, (socklen_t)keylen) < 0) {
		PUT_ERROR_ERRNO(ctx->provctx, STM32_R_CIPHER_INIT_FAILED,
				"AF_ALG ALG_SET_KEY");
		return 0;
	}

	/* The tag size must be set before any operation. */
	if (setsockopt(ctx->tf_fd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE,
		 NULL, (socklen_t)taglen) < 0) {
		PUT_ERROR_ERRNO(ctx->provctx, STM32_R_CIPHER_INIT_FAILED,
				"AF_ALG ALG_SET_AEAD_AUTHSIZE");
		return 0;
	}

	return 1;
}

/* Send the entire buffer, then finalize the request (sendmsg with zero length and no MSG_MORE). */
static int afalg_send_all(STM32_AEAD_HW_CTX *ctx, int op_fd, struct msghdr *msg,
			  const unsigned char *buf, size_t len)
{
	struct iovec iov;
	size_t sent = 0;
	ssize_t ret;

	while (sent < len) {
		iov.iov_base = (void *)(uintptr_t)(buf + sent);
		iov.iov_len = len - sent;
		msg->msg_iov = &iov;
		msg->msg_iovlen = 1;

		ret = sendmsg(op_fd, msg, MSG_MORE);
		if (ret < 0) {
			PUT_ERROR_ERRNO(ctx->provctx, STM32_R_CIPHER_UPDATE_FAILED,
					"AF_ALG AEAD sendmsg()");
			return 0;
		}
		if (ret == 0) {
			PUT_ERROR(ctx->provctx, STM32_R_CIPHER_UPDATE_FAILED,
				 "AF_ALG AEAD sendmsg() made no progress");
			return 0;
		}
		sent += (size_t)ret;

		/* the cmsg should only accompany the first send */
		msg->msg_control = NULL;
		msg->msg_controllen = 0;
	}

	/* Finalize the request : without this sendmsg, recvmsg() blocks (ctx->more). */
	{
		struct msghdr fin;

		memset(&fin, 0, sizeof(fin));
		if (sendmsg(op_fd, &fin, 0) < 0) {
			PUT_ERROR_ERRNO(ctx->provctx, STM32_R_CIPHER_UPDATE_FAILED,
					"AF_ALG AEAD final sendmsg()");
			return 0;
		}
	}

	return 1;
}

static int afalg_aead_crypt(STM32_AEAD_HW_CTX *ctx, int encrypt, const unsigned char *iv, size_t ivlen,
			 const unsigned char *aad, size_t aadlen, const unsigned char *in, size_t inl,
			 unsigned char *out, size_t *outl, unsigned char *tag, size_t taglen)
{
	int op_fd = -1;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct af_alg_iv *alg_iv;
	unsigned char *inbuf = NULL;
	unsigned char *recvbuf = NULL;
	size_t inbuf_len;
	size_t recvbuf_len;
	uint32_t assoclen_val;
	ssize_t ret;
	int rv = STM32_AEAD_ERROR;

	char cbuf[CMSG_SPACE(sizeof(uint32_t))
		 + CMSG_SPACE(sizeof(struct af_alg_iv) + MAX_IV_SIZE)
		 + CMSG_SPACE(sizeof(uint32_t))];

	if (ctx == NULL || ctx->tf_fd < 0 || outl == NULL)
		return STM32_AEAD_ERROR;
	if (iv == NULL || ivlen == 0 || ivlen > MAX_IV_SIZE)
		return STM32_AEAD_ERROR;
	if (taglen == 0 || taglen > MAX_TAG_SIZE)
		return STM32_AEAD_ERROR;
	if (aadlen > 0 && aad == NULL)
		return STM32_AEAD_ERROR;
	if (inl > 0 && (in == NULL || out == NULL))
		return STM32_AEAD_ERROR;

	*outl = 0;

	if (encrypt) {
		inbuf_len = aadlen + inl;
		recvbuf_len = aadlen + inl + taglen;
	} else {
		inbuf_len = aadlen + inl + taglen;
		recvbuf_len = aadlen + inl;
	}

	op_fd = accept(ctx->tf_fd, NULL, NULL);
	if (op_fd < 0) {
		PUT_ERROR_ERRNO(ctx->provctx, STM32_R_CIPHER_UPDATE_FAILED,
				"AF_ALG AEAD accept()");
		return STM32_AEAD_ERROR;
	}

	inbuf = OPENSSL_malloc(inbuf_len > 0 ? inbuf_len : 1);
	if (inbuf == NULL)
		goto out;

	if (aadlen > 0)
		memcpy(inbuf, aad, aadlen);
	if (inl > 0)
		memcpy(inbuf + aadlen, in, inl);
	if (!encrypt)
		memcpy(inbuf + aadlen + inl, tag, taglen);

	memset(&msg, 0, sizeof(msg));
	memset(cbuf, 0, sizeof(cbuf));
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	/* cmsg 1 : operation */
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
	{
		uint32_t op = encrypt ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;

		memcpy(CMSG_DATA(cmsg), &op, sizeof(op));
	}

	/* cmsg 2 : IV (already formatted for by aead.c) */
	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + ivlen);
	alg_iv = (struct af_alg_iv *)CMSG_DATA(cmsg);
	alg_iv->ivlen = (uint32_t)ivlen;
	memcpy(alg_iv->iv, iv, ivlen);

	/* cmsg 3 : length of AAD */
	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
	cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
	assoclen_val = (uint32_t)aadlen;
	memcpy(CMSG_DATA(cmsg), &assoclen_val, sizeof(assoclen_val));

	/* msg_controllen must reflect the actual size used */
	msg.msg_controllen = CMSG_SPACE(sizeof(uint32_t))
			 + CMSG_SPACE(sizeof(struct af_alg_iv) + ivlen)
			 + CMSG_SPACE(sizeof(uint32_t));

	if (!afalg_send_all(ctx, op_fd, &msg, inbuf, inbuf_len))
		goto out;

	recvbuf = OPENSSL_malloc(recvbuf_len > 0 ? recvbuf_len : 1);
	if (recvbuf == NULL)
		goto out;

	/* One read() : a partial read would produce a wrong result. */
	ret = read(op_fd, recvbuf, recvbuf_len);
	if (ret < 0) {
		if (errno == EBADMSG) {
			rv = STM32_AEAD_AUTH_FAIL;
			goto out;
		}
		PUT_ERROR_ERRNO(ctx->provctx, STM32_R_CIPHER_UPDATE_FAILED,
				"AF_ALG AEAD read()");
		goto out;
	}
	if ((size_t)ret != recvbuf_len) {
		PUT_ERROR(ctx->provctx, STM32_R_CIPHER_UPDATE_FAILED,
			 "AF_ALG AEAD short read: %zd != %zu",
			 ret, recvbuf_len);
		goto out;
	}

	/* The kernel output starts with the AAD, so skip it. */
	if (inl > 0)
		memcpy(out, recvbuf + aadlen, inl);
	if (encrypt)
		memcpy(tag, recvbuf + aadlen + inl, taglen);

	*outl = inl;
	rv = STM32_AEAD_OK;

out:
	if (inbuf != NULL) {
		OPENSSL_cleanse(inbuf, inbuf_len);
		OPENSSL_free(inbuf);
	}
	if (recvbuf != NULL) {
		OPENSSL_cleanse(recvbuf, recvbuf_len);
		OPENSSL_free(recvbuf);
	}
	if (op_fd >= 0)
		close(op_fd);
	return rv;
}

int stm32_aead_encrypt(STM32_AEAD_HW_CTX *ctx, const unsigned char *iv, size_t ivlen,
		 const unsigned char *aad, size_t aadlen, const unsigned char *in, 
		 size_t inl, unsigned char *out, size_t *outl, unsigned char *tag, 
		 size_t taglen)
{
	return afalg_aead_crypt(ctx, 1, iv, ivlen, aad, aadlen, in, inl, out, 
				outl, tag, taglen);
}

int stm32_aead_decrypt(STM32_AEAD_HW_CTX *ctx, const unsigned char *iv, size_t ivlen,
		 const unsigned char *aad, size_t aadlen, const unsigned char *in, 
		 size_t inl, unsigned char *out, size_t *outl, const unsigned char *tag, 
		 size_t taglen)
{
	return afalg_aead_crypt(ctx, 0, iv, ivlen, aad, aadlen, in, inl, out, 
				outl, (unsigned char *)(uintptr_t)tag, taglen);
}