#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

#include <openssl/core.h>
#include <openssl/crypto.h>
#include "hmac.h"
#include "../include/err.h"

#define AFALG_HMAC_BUF_MAX (64 * 1024)   /* 64 KB accumulation buffer */

/* prototypes AF_ALG MAC functions */
static void stm32_afalg_hmac_close_fd(int *fd);
static int  stm32_afalg_hmac_open_tfm(PROV_CTX *provctx, const char *alg_name);
static int  stm32_afalg_hmac_set_key(PROV_CTX *provctx, int tf_fd,
                                      const unsigned char *key, size_t keylen);
static int  stm32_afalg_hmac_open_op(PROV_CTX *provctx, int tf_fd);
static int  stm32_afalg_hmac_send_all(PROV_CTX *provctx, int fd,
                                       const unsigned char *buf,
                                       size_t len, int flags);

/*********************************************************************
 *
 * AF_ALG Mac context
 *
 *****/
struct __stm32_hmac_ctx_st__ {
    PROV_CTX *provctx;
    int tf_fd;
    int op_fd;
    const char *alg_name;
    size_t digest_len;
    /* accumulation buffer */
    unsigned char *buf;
    size_t buf_len;
    size_t buf_max;
};

/* Helpers */
static void stm32_afalg_hmac_close_fd(int *fd)
{
    if (fd && *fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

static int stm32_afalg_hmac_open_tfm(PROV_CTX *provctx, const char *alg_name)
{
    struct sockaddr_alg sa;
    int tf_fd;

    tf_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (tf_fd < 0) {
        PUT_ERROR_ERRNO(provctx, STM32_R_HASH_NEWCTX_FAILED, "AF_ALG HMAC socket");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    OPENSSL_strlcpy((char *)sa.salg_type, "hash", sizeof(sa.salg_type));
    OPENSSL_strlcpy((char *)sa.salg_name, alg_name, sizeof(sa.salg_name));

    if (bind(tf_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        PUT_ERROR_ERRNO(provctx, STM32_R_HASH_NEWCTX_FAILED, "AF_ALG HMAC bind");
        close(tf_fd);
        return -1;
    }

    return tf_fd;
}

/*
 * The HMAC key is set on tf_fd via setsockopt BEFORE accept().
 * Each accept() after set_key creates an op_fd bound to that key.
 */
static int stm32_afalg_hmac_set_key(PROV_CTX *provctx, int tf_fd,
                                     const unsigned char *key, size_t keylen)
{
    if (setsockopt(tf_fd, SOL_ALG, ALG_SET_KEY, key, (socklen_t)keylen) < 0) {
        PUT_ERROR_ERRNO(provctx, STM32_R_HASH_INIT_FAILED,
                        "AF_ALG HMAC ALG_SET_KEY");
        return 0;
    }
    return 1;
}

static int stm32_afalg_hmac_open_op(PROV_CTX *provctx, int tf_fd)
{
    int op_fd = accept(tf_fd, NULL, NULL);
    if (op_fd < 0) {
        PUT_ERROR_ERRNO(provctx, STM32_R_HASH_INIT_FAILED, "AF_ALG HMAC accept");
        return -1;
    }
    return op_fd;
}

static int stm32_afalg_hmac_send_all(PROV_CTX *provctx, int fd,
                                      const unsigned char *buf,
                                      size_t len, int flags)
{
    size_t  off = 0;
    ssize_t written;

    while (off < len) {
        written = send(fd, buf + off, len - off, flags);
        if (written < 0) {
            PUT_ERROR_ERRNO(provctx, STM32_R_HASH_UPDATE_FAILED,
                            "AF_ALG HMAC send");
            return 0;
        }
        if (written == 0) {
            PUT_ERROR(provctx, STM32_R_HASH_UPDATE_FAILED,
                      "short send on AF_ALG HMAC socket");
            return 0;
        }
        off += (size_t)written;
    }
    return 1;
}

/*********************************************************************
 *
 * Public interface  used by hmac.c
 *
 *****/
STM32_HMAC_CTX *stm32_hmac_newctx(void *vprovctx, const char *alg_name,
                                   size_t digest_len)
{
    PROV_CTX *provctx = (PROV_CTX *)vprovctx;
    STM32_HMAC_CTX *ctx;

    if (!provctx || !alg_name || digest_len == 0) {
        PUT_ERROR(provctx, STM32_R_INVALID_ARGUMENT,
                  "invalid AF_ALG HMAC newctx arguments");
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx) {
        PUT_ERROR(provctx, STM32_R_HASH_NEWCTX_FAILED,
                  "failed to allocate AF_ALG HMAC context");
        return NULL;
    }

    ctx->provctx = provctx;
    ctx->tf_fd = -1;
    ctx->op_fd = -1;
    ctx->alg_name = alg_name;
    ctx->digest_len = digest_len;
    ctx->buf_max = AFALG_HMAC_BUF_MAX;
    ctx->buf_len = 0;

    /* Allocate accumulation buffer once for the lifetime of the context */
    ctx->buf = OPENSSL_malloc(ctx->buf_max);
    if (!ctx->buf) {
        PUT_ERROR(provctx, STM32_R_HASH_NEWCTX_FAILED,
                  "failed to allocate AF_ALG HMAC accumulation buffer");
        OPENSSL_free(ctx);
        return NULL;
    }

    ctx->tf_fd = stm32_afalg_hmac_open_tfm(provctx, alg_name);
    if (ctx->tf_fd < 0) {
        OPENSSL_free(ctx->buf);
        OPENSSL_free(ctx);
        return NULL;
    }

    return ctx;
}

void stm32_hmac_freectx(STM32_HMAC_CTX *ctx)
{
    if (!ctx) return;
    OPENSSL_free(ctx->buf);
    stm32_afalg_hmac_close_fd(&ctx->op_fd);
    stm32_afalg_hmac_close_fd(&ctx->tf_fd);
    OPENSSL_free(ctx);
}

/*
 * init() = set key on tf_fd + accept() a fresh op_fd.
 * Can be called again to change the key between operations.
 */
int stm32_hmac_init(STM32_HMAC_CTX *ctx,
                    const unsigned char *key, size_t keylen)
{
    if (!ctx || ctx->tf_fd < 0) {
        PUT_ERROR(ctx->provctx, STM32_R_HASH_INIT_FAILED,
                  "invalid AF_ALG HMAC transform fd");
        return 0;
    }
    if (!key || keylen == 0) {
        PUT_ERROR(ctx->provctx, STM32_R_INVALID_ARGUMENT,
                  "HMAC key is NULL or empty");
        return 0;
    }

    /* Reset accumulation buffer and close previous op_fd */
    ctx->buf_len = 0;
    stm32_afalg_hmac_close_fd(&ctx->op_fd);

    /* Set key on tf_fd */
    if (!stm32_afalg_hmac_set_key(ctx->provctx, ctx->tf_fd, key, keylen))
        return 0;

    /* accept() → new op_fd bound to this key */
    ctx->op_fd = stm32_afalg_hmac_open_op(ctx->provctx, ctx->tf_fd);
    if (ctx->op_fd < 0)
        return 0;

    return 1;
}

int stm32_hmac_update(STM32_HMAC_CTX *ctx, const unsigned char *in, size_t inl)
{
    size_t space;
    size_t to_copy;

    if (!ctx) return 0;
    if (ctx->op_fd < 0) {
        PUT_ERROR(ctx->provctx, STM32_R_HASH_UPDATE_FAILED,
                  "HMAC operation not initialized (call init first)");
        return 0;
    }
    if (inl == 0) return 1;
    if (!in) {
        PUT_ERROR(ctx->provctx, STM32_R_INVALID_ARGUMENT,
                  "input buffer is NULL with non-zero length");
        return 0;
    }

    /*
     * Accumulate data into the buffer.
     * When the buffer reaches buf_max (64 KB), flush it to the kernel
     * with MSG_MORE and reset the buffer.
     */
    while (inl > 0) {
        space = ctx->buf_max - ctx->buf_len;
        to_copy = (inl < space) ? inl : space;

        memcpy(ctx->buf + ctx->buf_len, in, to_copy);
        ctx->buf_len += to_copy;
        in += to_copy;
        inl -= to_copy;

        /* Buffer full: flush to kernel, more data will follow */
        if (ctx->buf_len == ctx->buf_max) {
            if (!stm32_afalg_hmac_send_all(ctx->provctx, ctx->op_fd,
                                            ctx->buf, ctx->buf_len, MSG_MORE))
                return 0;
            ctx->buf_len = 0;
        }
    }

    return 1;
}

int stm32_hmac_final(STM32_HMAC_CTX *ctx, unsigned char *out, size_t *outl)
{
    ssize_t r;

    if (!ctx) return 0;
    if (ctx->op_fd < 0) {
        PUT_ERROR(ctx->provctx, STM32_R_HASH_FINAL_FAILED,
                  "HMAC operation not initialized");
        return 0;
    }
    if (!out || !outl) {
        PUT_ERROR(ctx->provctx, STM32_R_INVALID_ARGUMENT,
                  "output buffer or length is NULL");
        return 0;
    }

    /*
     * Flush remaining data without MSG_MORE to signal end of message
     * and trigger hmac_final() in the kernel.
     *
     * buf_len == 0 means no update() was called (empty message):
     * send a 0-byte frame without MSG_MORE to finalize the empty HMAC.
     */
    if (ctx->buf_len > 0) {
        if (!stm32_afalg_hmac_send_all(ctx->provctx, ctx->op_fd,
                                        ctx->buf, ctx->buf_len, 0))
            return 0;
    } else {
        if (send(ctx->op_fd, ctx->buf, 0, 0) < 0) {
            PUT_ERROR_ERRNO(ctx->provctx, STM32_R_HASH_FINAL_FAILED,
                            "AF_ALG HMAC send (empty message)");
            return 0;
        }
    }

    ctx->buf_len = 0;

    r = recv(ctx->op_fd, out, ctx->digest_len, 0);
    if (r < 0) {
        PUT_ERROR_ERRNO(ctx->provctx, STM32_R_HASH_FINAL_FAILED,
                        "AF_ALG HMAC recv");
        return 0;
    }
    if ((size_t)r != ctx->digest_len) {
        PUT_ERROR(ctx->provctx, STM32_R_HASH_FINAL_FAILED,
                  "incorrect HMAC length: got %zd, expected %zu",
                  r, ctx->digest_len);
        return 0;
    }

    *outl = (size_t)r;
    return 1;
}