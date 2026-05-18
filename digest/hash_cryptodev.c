#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "digest.h"
#include "../include/err.h"

#define CRYPTODEV_BUF_MAX (256 * 1024)  /* 256 KB accumulation buffer */

/* prototypes Cryptodev helpers / / static */
static unsigned int stm32_cryptodev_mac_from_name(const char *alg_name);  
static void stm32_cryptodev_close_session(STM32_HASH_CTX *ctx);
static int stm32_cryptodev_open_session(STM32_HASH_CTX *ctx);
static int stm32_cryptodev_crypt(STM32_HASH_CTX *ctx,
                                 const unsigned char *in, size_t inl,
                                 unsigned int flags,
                                 unsigned char *mac);

/*********************************************************************
 *
 *  Contexte OpenSSL for digest operation using Cryptodev
 *
 *****/
struct stm32_hash_ctx_st {
    PROV_CTX *provctx;
    int cfd;
    struct session_op sess;
    int session_opened;
    unsigned int mac_alg;
    const char *alg_name;
    size_t digest_len;
    int started;
    unsigned char *buf;
    size_t buf_len;
    size_t buf_max;
};

/*********************************************************************
 *
 *  Helpers functions for Cryptodev interfacing
 *
 *****/
static unsigned int stm32_cryptodev_mac_from_name(const char *alg_name)
{
    if (alg_name == NULL)
        return 0;

    if (strcmp(alg_name, "sha1") == 0)
        return CRYPTO_SHA1;

    if (strcmp(alg_name, "sha224") == 0)
        return CRYPTO_SHA2_224;

    if (strcmp(alg_name, "sha256") == 0)
        return CRYPTO_SHA2_256;

    if (strcmp(alg_name, "sha384") == 0)
        return CRYPTO_SHA2_384;

    if (strcmp(alg_name, "sha512") == 0)
        return CRYPTO_SHA2_512;
    /*
     * SHA3 not available in cryptodev.h
     */

    return 0;
}

static void stm32_cryptodev_close_session(STM32_HASH_CTX *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->cfd >= 0 && ctx->session_opened) {
        if (ioctl(ctx->cfd, CIOCFSESSION, &ctx->sess.ses) < 0) {
            PUT_ERROR_ERRNO(ctx->provctx, STM32_R_HASH_FINAL_FAILED,
                            "cryptodev CIOCFSESSION");
        }
        ctx->session_opened = 0;
    }
}

static int stm32_cryptodev_open_session(STM32_HASH_CTX *ctx)
{
    if (ctx == NULL)
        return 0;

    memset(&ctx->sess, 0, sizeof(ctx->sess));
    ctx->sess.mac = ctx->mac_alg;

    if (ioctl(ctx->cfd, CIOCGSESSION, &ctx->sess) < 0) {
        PUT_ERROR_ERRNO(ctx->provctx, STM32_R_HASH_INIT_FAILED,
                        "cryptodev CIOCGSESSION");
        return 0;
    }

    ctx->session_opened = 1;
    return 1;
}

static int stm32_cryptodev_crypt(STM32_HASH_CTX *ctx,
                                 const unsigned char *in, size_t inl,
                                 unsigned int flags,
                                 unsigned char *mac)
{
    struct crypt_op cop;

    if (ctx == NULL)
        return 0;

    memset(&cop, 0, sizeof(cop));
    cop.ses = ctx->sess.ses;
    cop.op = COP_ENCRYPT;
    cop.flags = flags;
    cop.len = (unsigned int)inl;
    cop.src = (unsigned char *)in;
    cop.dst = NULL;
    cop.mac = mac;

    if (ioctl(ctx->cfd, CIOCCRYPT, &cop) < 0) {
        PUT_ERROR_ERRNO(ctx->provctx, STM32_R_HASH_UPDATE_FAILED,
                        "cryptodev CIOCCRYPT");
        return 0;
    }

    return 1;
}

/*********************************************************************
 *
 *  Setup
 *  Public Interface used by digest.c
 *
 *****/
STM32_HASH_CTX *stm32_hash_newctx(void *vprovctx, const char *alg_name,
                                  size_t digest_len)
{
    PROV_CTX *provctx = (PROV_CTX *)vprovctx;
    STM32_HASH_CTX *ctx;
    unsigned int mac_alg;

    if (provctx == NULL)
        return NULL;

    if (alg_name == NULL || digest_len == 0) {
        PUT_ERROR(provctx, STM32_R_INVALID_ARGUMENT,
                  "invalid cryptodev hash newctx arguments");
        return NULL;
    }

    mac_alg = stm32_cryptodev_mac_from_name(alg_name);
    if (mac_alg == 0) {
        PUT_ERROR(provctx, STM32_R_UNSUPPORTED_OPERATION,
                  "cryptodev unsupported digest: %s", alg_name);
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        PUT_ERROR(provctx, STM32_R_HASH_NEWCTX_FAILED,
                  "failed to allocate cryptodev hash context");
        return NULL;
    }

    ctx->provctx = provctx;
    ctx->cfd = -1;
    ctx->session_opened = 0;
    ctx->mac_alg = mac_alg;
    ctx->alg_name = alg_name;
    ctx->digest_len = digest_len;
    ctx->started = 0;
    ctx->buf_max = CRYPTODEV_BUF_MAX;
    ctx->buf_len = 0;

    /* Allocate the accumulation buffer once for the lifetime of the context */
    ctx->buf = OPENSSL_malloc(ctx->buf_max);
    if (ctx->buf == NULL) {
        PUT_ERROR(provctx, STM32_R_HASH_NEWCTX_FAILED,
                  "failed to allocate cryptodev accumulation buffer");
        OPENSSL_free(ctx);
        return NULL;
    }

    ctx->cfd = open("/dev/crypto", O_RDWR, 0);
    if (ctx->cfd < 0) {
        PUT_ERROR_ERRNO(provctx, STM32_R_HASH_NEWCTX_FAILED,
                        "open /dev/crypto");
        OPENSSL_free(ctx->buf);
        OPENSSL_free(ctx);
        return NULL;
    }

    return ctx;
}

void stm32_hash_freectx(STM32_HASH_CTX *ctx)
{
    if (ctx == NULL)
        return;

    stm32_cryptodev_close_session(ctx);

    if (ctx->cfd >= 0) {
        close(ctx->cfd);
        ctx->cfd = -1;
    }

    OPENSSL_free(ctx->buf);
    OPENSSL_free(ctx);
}

int stm32_hash_init(STM32_HASH_CTX *ctx)
{
    if (ctx == NULL)
        return 0;

    if (ctx->cfd < 0) {
        PUT_ERROR(ctx->provctx, STM32_R_HASH_INIT_FAILED,
                  "invalid cryptodev fd");
        return 0;
    }

    /* Reset accumulation buffer and reopen session */
    ctx->buf_len = 0;
    ctx->started = 0;

    stm32_cryptodev_close_session(ctx);

    if (!stm32_cryptodev_open_session(ctx))
        return 0;

    return 1;
}

int stm32_hash_update(STM32_HASH_CTX *ctx, const unsigned char *in, size_t inl)
{
    size_t       space;
    size_t       to_copy;
    unsigned int flags;

    if (ctx == NULL)
        return 0;

    if (!ctx->session_opened) {
        PUT_ERROR(ctx->provctx, STM32_R_HASH_UPDATE_FAILED,
                  "cryptodev session not initialized");
        return 0;
    }

    if (inl == 0)
        return 1;

    if (in == NULL) {
        PUT_ERROR(ctx->provctx, STM32_R_INVALID_ARGUMENT,
                  "input buffer is NULL with non-zero length");
        return 0;
    }

    /*
     * Accumulate data into the buffer.
     * When the buffer reaches buf_max (256 KB), flush it to the driver
     * and reset the buffer.
     * Repeat until all input is consumed.
     */
    while (inl > 0) {
        space   = ctx->buf_max - ctx->buf_len;
        to_copy = (inl < space) ? inl : space;

        memcpy(ctx->buf + ctx->buf_len, in, to_copy);
        ctx->buf_len += to_copy;
        in           += to_copy;
        inl          -= to_copy;

        /* Buffer full: flush to driver, more data will follow */
        if (ctx->buf_len == ctx->buf_max) {
            flags = COP_FLAG_UPDATE;
            if (!ctx->started)
                flags |= COP_FLAG_RESET;

            if (!stm32_cryptodev_crypt(ctx, ctx->buf, ctx->buf_len, flags, NULL))
                return 0;

            ctx->started = 1;
            ctx->buf_len = 0;
        }
    }

    return 1;
}

int stm32_hash_final(STM32_HASH_CTX *ctx, unsigned char *out, size_t *outl)
{
    unsigned int flags;

    if (ctx == NULL)
        return 0;

    if (!ctx->session_opened) {
        PUT_ERROR(ctx->provctx, STM32_R_HASH_FINAL_FAILED,
                  "cryptodev session not initialized");
        return 0;
    }

    if (out == NULL || outl == NULL) {
        PUT_ERROR(ctx->provctx, STM32_R_INVALID_ARGUMENT,
                  "output buffer or output length is NULL");
        return 0;
    }

    /*
     * Flush any remaining buffered data before finalizing.
     * If buf_len == 0 and started == 0: empty message, skip UPDATE.
     */
    if (ctx->buf_len > 0) {
        flags = COP_FLAG_UPDATE;
        if (!ctx->started)
            flags |= COP_FLAG_RESET;

        if (!stm32_cryptodev_crypt(ctx, ctx->buf, ctx->buf_len, flags, NULL))
            return 0;

        ctx->started = 1;
        ctx->buf_len = 0;
    }

    /* Finalize: retrieve the digest */
    flags = COP_FLAG_FINAL;
    if (!ctx->started)
        flags |= COP_FLAG_RESET;

    if (!stm32_cryptodev_crypt(ctx, NULL, 0, flags, out))
        return 0;

    *outl = ctx->digest_len;
    ctx->started = 0;

    return 1;
}
