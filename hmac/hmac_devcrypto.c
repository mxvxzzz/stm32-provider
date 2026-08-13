#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>

#include <openssl/core.h>
#include <openssl/crypto.h>
#include "hmac.h"
#include "../include/err.h"

#define CRYPTODEV_HMAC_BUF_MAX (256 * 1024)

/* prototypes Cryptodev MAC functions */
static unsigned int stm32_cryptodev_hmac_from_name(const char *alg_name);
static void stm32_cryptodev_hmac_close_session(STM32_HMAC_CTX *ctx);
static int stm32_cryptodev_hmac_open_session(STM32_HMAC_CTX *ctx,
                                               size_t keylen);
static int stm32_cryptodev_hmac_crypt(STM32_HMAC_CTX *ctx,
                                        const unsigned char *in, size_t inl,
                                        unsigned int flags,
                                        unsigned char *mac);

/*********************************************************************
 *
 * Cryptodev context
 *
 *****/
struct __stm32_hmac_ctx_st__ {
    PROV_CTX *provctx;
    int cfd;
    struct session_op sess;
    int session_opened;
    unsigned int mac_alg;
    const char *alg_name;
    size_t digest_len;
    int          started;
    /* key copy! cryptodev requires pointer to remain valid for session */
    unsigned char *key_buf;
    size_t key_len;
    /* accumulation buffer */
    unsigned char *buf;
    size_t buf_len;
    size_t buf_max;
};

/*********************************************************************
 *
 * Helpers
 *****/
static unsigned int stm32_cryptodev_hmac_from_name(const char *alg_name)
{
    if (!alg_name) 
        return 0;

    if (strcmp(alg_name, "hmac(md5)") == 0)
        return CRYPTO_MD5_HMAC;

    if (strcmp(alg_name, "hmac(sha1)") == 0)
        return CRYPTO_SHA1_HMAC;

    if (strcmp(alg_name, "hmac(sha224)") == 0)
        return CRYPTO_SHA2_224_HMAC;

    if (strcmp(alg_name, "hmac(sha256)") == 0)
        return CRYPTO_SHA2_256_HMAC;

    if (strcmp(alg_name, "hmac(sha384)") == 0)
        return CRYPTO_SHA2_384_HMAC;

    if (strcmp(alg_name, "hmac(sha512)") == 0)
        return CRYPTO_SHA2_512_HMAC;
    
    /* SHA3 not supported by cryptodev */
    return 0;
}

static void stm32_cryptodev_hmac_close_session(STM32_HMAC_CTX *ctx)
{
    if (!ctx) 
        return;
    if (ctx->cfd >= 0 && ctx->session_opened) {
        if (ioctl(ctx->cfd, CIOCFSESSION, &ctx->sess.ses) < 0)
            PUT_ERROR_ERRNO(ctx->provctx, STM32_R_HASH_FINAL_FAILED,
                            "cryptodev HMAC CIOCFSESSION");
        ctx->session_opened = 0;
    }
}

static int stm32_cryptodev_hmac_open_session(STM32_HMAC_CTX *ctx,
                                              size_t keylen)
{
    memset(&ctx->sess, 0, sizeof(ctx->sess));
    ctx->sess.mac = ctx->mac_alg;
    ctx->sess.mackey = ctx->key_buf;
    ctx->sess.mackeylen = (uint32_t)keylen;

    if (ioctl(ctx->cfd, CIOCGSESSION, &ctx->sess) < 0) {
        PUT_ERROR_ERRNO(ctx->provctx, STM32_R_HASH_INIT_FAILED,
                        "cryptodev HMAC CIOCGSESSION");
        return 0;
    }

    ctx->session_opened = 1;
    return 1;
}

static int stm32_cryptodev_hmac_crypt(STM32_HMAC_CTX *ctx,
                                       const unsigned char *in, size_t inl,
                                       unsigned int flags,
                                       unsigned char *mac)
{
    struct crypt_op cop;

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
                        "cryptodev HMAC CIOCCRYPT");
        return 0;
    }
    return 1;
}

/*********************************************************************
 *
 *
 * Public interface used by hmac.c
 *****/
STM32_HMAC_CTX *stm32_hmac_newctx(void *vprovctx, const char *alg_name,
                                   size_t digest_len)
{
    PROV_CTX *provctx = (PROV_CTX *)vprovctx;
    STM32_HMAC_CTX *ctx;
    unsigned int mac_alg;

    if (!provctx || !alg_name || digest_len == 0) {
        PUT_ERROR(provctx, STM32_R_INVALID_ARGUMENT,
                  "invalid cryptodev HMAC newctx arguments");
        return NULL;
    }

    mac_alg = stm32_cryptodev_hmac_from_name(alg_name);
    if (mac_alg == 0) {
        PUT_ERROR(provctx, STM32_R_UNSUPPORTED_OPERATION,
                  "cryptodev unsupported HMAC: %s", alg_name);
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx) {
        PUT_ERROR(provctx, STM32_R_HASH_NEWCTX_FAILED,
                  "failed to allocate cryptodev HMAC context");
        return NULL;
    }

    ctx->provctx = provctx;
    ctx->cfd = -1;
    ctx->mac_alg = mac_alg;
    ctx->alg_name = alg_name;
    ctx->digest_len = digest_len;
    ctx->buf_max = CRYPTODEV_HMAC_BUF_MAX;
    ctx->buf_len = 0;

    /* Allocate accumulation buffer once for the lifetime of the context */
    ctx->buf = OPENSSL_malloc(ctx->buf_max);
    if (!ctx->buf) {
        PUT_ERROR(provctx, STM32_R_HASH_NEWCTX_FAILED,
                  "failed to allocate cryptodev HMAC accumulation buffer");
        OPENSSL_free(ctx);
        return NULL;
    }

    ctx->cfd = open("/dev/crypto", O_RDWR, 0);
    if (ctx->cfd < 0) {
        PUT_ERROR_ERRNO(provctx, STM32_R_HASH_NEWCTX_FAILED,
                        "open /dev/crypto for HMAC");
        OPENSSL_free(ctx->buf);
        OPENSSL_free(ctx);
        return NULL;
    }

    return ctx;
}

void stm32_hmac_freectx(STM32_HMAC_CTX *ctx)
{
    if (!ctx) 
        return;
    
    stm32_cryptodev_hmac_close_session(ctx);
    if (ctx->cfd >= 0) {
        close(ctx->cfd);
        ctx->cfd = -1;
    }
    if (ctx->key_buf) {
        OPENSSL_cleanse(ctx->key_buf, ctx->key_len);
        OPENSSL_free(ctx->key_buf);
    }
    OPENSSL_free(ctx->buf);
    OPENSSL_free(ctx);
}

int stm32_hmac_init(STM32_HMAC_CTX *ctx,
                    const unsigned char *key, size_t keylen)
{
    if (!ctx || ctx->cfd < 0) {
        PUT_ERROR(ctx->provctx, STM32_R_HASH_INIT_FAILED,
                  "invalid cryptodev HMAC fd");
        return 0;
    }
    if (!key || keylen == 0) {
        PUT_ERROR(ctx->provctx, STM32_R_INVALID_ARGUMENT,
                  "HMAC key is NULL or empty");
        return 0;
    }

    /* Reset accumulation buffer */
    ctx->buf_len = 0;
    ctx->started = 0;

    /* Close previous session */
    stm32_cryptodev_hmac_close_session(ctx);

    /* Copy key — cryptodev needs pointer valid for entire session */
    if (ctx->key_buf) {
        OPENSSL_cleanse(ctx->key_buf, ctx->key_len);
        OPENSSL_free(ctx->key_buf);
    }
    ctx->key_buf = OPENSSL_malloc(keylen);
    if (!ctx->key_buf) {
        PUT_ERROR(ctx->provctx, STM32_R_HASH_INIT_FAILED,
                  "failed to allocate HMAC key buffer");
        return 0;
    }
    memcpy(ctx->key_buf, key, keylen);
    ctx->key_len = keylen;

    /* Open new session with key */
    if (!stm32_cryptodev_hmac_open_session(ctx, keylen))
        return 0;

    return 1;
}

int stm32_hmac_update(STM32_HMAC_CTX *ctx, const unsigned char *in, size_t inl)
{
    size_t space;
    size_t to_copy;
    unsigned int flags;

    if (!ctx) return 0;
    if (!ctx->session_opened) {
        PUT_ERROR(ctx->provctx, STM32_R_HASH_UPDATE_FAILED,
                  "cryptodev HMAC session not initialized");
        return 0;
    }
    if (inl == 0)
        return 1;
    
    if (!in) {
        PUT_ERROR(ctx->provctx, STM32_R_INVALID_ARGUMENT,
                  "input buffer is NULL with non-zero length");
        return 0;
    }

    /*
     * Accumulate data into the buffer.
     * When the buffer reaches buf_max (256 KB), flush it to the driver
     * and reset the buffer.
     */
    while (inl > 0) {
        space = ctx->buf_max - ctx->buf_len;
        to_copy = (inl < space) ? inl : space;

        memcpy(ctx->buf + ctx->buf_len, in, to_copy);
        ctx->buf_len += to_copy;
        in += to_copy;
        inl -= to_copy;

        /* Buffer full: flush to driver, more data will follow */
        if (ctx->buf_len == ctx->buf_max) {
            flags = COP_FLAG_UPDATE;
            if (!ctx->started)
                flags |= COP_FLAG_RESET;

            if (!stm32_cryptodev_hmac_crypt(ctx, ctx->buf, ctx->buf_len,
                                             flags, NULL))
                return 0;

            ctx->started = 1;
            ctx->buf_len = 0;
        }
    }

    return 1;
}

int stm32_hmac_final(STM32_HMAC_CTX *ctx, unsigned char *out, size_t *outl)
{
    unsigned int flags;

    if (!ctx) 
        return 0;
    
    if (!ctx->session_opened) {
        PUT_ERROR(ctx->provctx, STM32_R_HASH_FINAL_FAILED,
                  "cryptodev HMAC session not initialized");
        return 0;
    }
    if (!out || !outl) {
        PUT_ERROR(ctx->provctx, STM32_R_INVALID_ARGUMENT,
                  "output buffer or length is NULL");
        return 0;
    }

    /*
     * Flush remaining buffered data before finalizing.
     * If buf_len == 0 and started == 0: empty message, skip UPDATE.
     */
    if (ctx->buf_len > 0) {
        flags = COP_FLAG_UPDATE;
        if (!ctx->started)
            flags |= COP_FLAG_RESET;

        if (!stm32_cryptodev_hmac_crypt(ctx, ctx->buf, ctx->buf_len,
                                         flags, NULL))
            return 0;

        ctx->started = 1;
        ctx->buf_len = 0;
    }

    /* Finalize: retrieve the HMAC */
    flags = COP_FLAG_FINAL;
    if (!ctx->started)
        flags |= COP_FLAG_RESET;   /* empty message case */

    if (!stm32_cryptodev_hmac_crypt(ctx, NULL, 0, flags, out))
        return 0;

    *outl = ctx->digest_len;
    ctx->started = 0;
    return 1;
}