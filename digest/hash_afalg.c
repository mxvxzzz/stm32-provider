#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "digest.h"
#include "../include/err.h"

#define AFALG_BUF_MAX (64 * 1024)   /* 64 KB accumulation buffer */

/* prototypes AF_ALG helpers / / static */
static void stm32_afalg_close_fd(int *fd);
static int stm32_afalg_open_tfm(PROV_CTX *provctx, const char *alg_name);
static int stm32_afalg_open_op(PROV_CTX *provctx, int tf_fd);
static int stm32_afalg_send_all(PROV_CTX *provctx, int fd,
                                const unsigned char *buf, 
                                size_t len, int flags);
                         
/*********************************************************************
 *
 *  Contexte OpenSSL for digest operation using AF_ALG
 *
 *****/
struct stm32_hash_ctx_st {
    PROV_CTX *provctx;
    int tf_fd;
    int op_fd;
    const char *alg_name;
    size_t digest_len;
    unsigned char *buf;
    size_t buf_len;
    size_t buf_max;
};

/*********************************************************************
 *
 *  Helpers functions for AF_ALG interfacing
 *
 *****/
static void stm32_afalg_close_fd(int *fd)
{
    if (fd != NULL && *fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

static int stm32_afalg_open_tfm(PROV_CTX *provctx, const char *alg_name)
{
    int tf_fd;
    struct sockaddr_alg sa;

    tf_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (tf_fd < 0) {
        PUT_ERROR_ERRNO(provctx, STM32_R_HASH_NEWCTX_FAILED, "AF_ALG socket");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    OPENSSL_strlcpy((char *)sa.salg_type, "hash", sizeof(sa.salg_type));
    OPENSSL_strlcpy((char *)sa.salg_name, alg_name, sizeof(sa.salg_name));

    if (bind(tf_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        PUT_ERROR_ERRNO(provctx, STM32_R_HASH_NEWCTX_FAILED, "AF_ALG bind");
        close(tf_fd);
        return -1;
    }

    return tf_fd;
}

static int stm32_afalg_open_op(PROV_CTX *provctx, int tf_fd)
{
    int op_fd;

    op_fd = accept(tf_fd, NULL, NULL);
    if (op_fd < 0) {
        PUT_ERROR_ERRNO(provctx, STM32_R_HASH_INIT_FAILED, "AF_ALG accept");
        return -1;
    }

    return op_fd;
}

static int stm32_afalg_send_all(PROV_CTX *provctx, int fd,
                                const unsigned char *buf,
                                size_t len, int flags)
{
    size_t off = 0;
    ssize_t written;

    while (off < len) {
        written = send(fd, buf + off, len - off, flags);
        if (written < 0) {
            PUT_ERROR_ERRNO(provctx, STM32_R_HASH_UPDATE_FAILED, "AF_ALG send");
            return 0;
        }
        if (written == 0) {
            PUT_ERROR(provctx, STM32_R_HASH_UPDATE_FAILED,
                      "short send on AF_ALG socket");
            return 0;
        }
        off += (size_t)written;
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

    if (provctx == NULL)
        return NULL;

    if (alg_name == NULL || digest_len == 0) {
        PUT_ERROR(provctx, STM32_R_INVALID_ARGUMENT,
                  "invalid hash newctx arguments");
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        PUT_ERROR(provctx, STM32_R_HASH_NEWCTX_FAILED,
                  "failed to allocate AF_ALG hash context");
        return NULL;
    }

    ctx->provctx = provctx;
    ctx->tf_fd = -1;
    ctx->op_fd = -1;
    ctx->digest_len = digest_len;
    ctx->alg_name = alg_name;
    ctx->buf_max = AFALG_BUF_MAX;
    ctx->buf_len = 0;

    /* Allocate the accumulation buffer once for the lifetime of the context */
    ctx->buf = OPENSSL_malloc(ctx->buf_max);
    if (ctx->buf == NULL) {
        PUT_ERROR(provctx, STM32_R_HASH_NEWCTX_FAILED,
                  "failed to allocate AF_ALG accumulation buffer");
        OPENSSL_free(ctx);
        return NULL;
    }

    ctx->tf_fd = stm32_afalg_open_tfm(provctx, alg_name);
    if (ctx->tf_fd < 0) {
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

    OPENSSL_free(ctx->buf);
    stm32_afalg_close_fd(&ctx->op_fd);
    stm32_afalg_close_fd(&ctx->tf_fd);
    OPENSSL_free(ctx);
}

int stm32_hash_init(STM32_HASH_CTX *ctx)
{
    if (ctx == NULL)
        return 0;

    if (ctx->tf_fd < 0){
        PUT_ERROR(ctx->provctx, STM32_R_HASH_INIT_FAILED,
                  "invalid AF_ALG transform socket");
        return 0;
    }

    /* Reset accumulation buffer and reopen operation socket */
    ctx->buf_len = 0;
    stm32_afalg_close_fd(&ctx->op_fd);

    ctx->op_fd = stm32_afalg_open_op(ctx->provctx, ctx->tf_fd);
    if (ctx->op_fd < 0) {
        return 0;
    }
    return 1;
}

int stm32_hash_update(STM32_HASH_CTX *ctx, const unsigned char *in, size_t inl)
{
    size_t space;
    size_t to_copy;

    if (ctx == NULL)
        return 0;

    if (ctx->op_fd < 0) {
        PUT_ERROR(ctx->provctx, STM32_R_HASH_UPDATE_FAILED,
                  "hash operation not initialized");
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
     * When the buffer reaches buf_max (64 KB), flush it to the kernel
     * with MSG_MORE (more data to come) and reset the buffer.
     * Repeat until all input is consumed.
     */
    while (inl > 0) {
        space   = ctx->buf_max - ctx->buf_len;
        to_copy = (inl < space) ? inl : space;

        memcpy(ctx->buf + ctx->buf_len, in, to_copy);
        ctx->buf_len += to_copy;
        in           += to_copy;
        inl          -= to_copy;

        /* Buffer full: flush to kernel, more data will follow */
        if (ctx->buf_len == ctx->buf_max) {
            if (!stm32_afalg_send_all(ctx->provctx, ctx->op_fd,
                                      ctx->buf, ctx->buf_len, MSG_MORE))
                return 0;
            ctx->buf_len = 0;
        }
    }

    return 1;
}

int stm32_hash_final(STM32_HASH_CTX *ctx, unsigned char *out, size_t *outl)
{
    ssize_t r;

    if (ctx == NULL)
        return 0;

    if (ctx->op_fd < 0) {
        PUT_ERROR(ctx->provctx, STM32_R_HASH_FINAL_FAILED,
                  "hash operation not initialized");
        return 0;
    }

    if (out == NULL || outl == NULL) {
        PUT_ERROR(ctx->provctx, STM32_R_INVALID_ARGUMENT,
                  "output buffer or output length is NULL");
        return 0;
    }

    /*
     * Flush remaining data without MSG_MORE to signal end of message
     * and trigger hash_final() in the kernel.
     *
     * buf_len == 0 means no update() was called (empty message):
     * send a 0-byte frame without MSG_MORE to finalize the empty hash.
     */
    if (ctx->buf_len > 0) {
        if (!stm32_afalg_send_all(ctx->provctx, ctx->op_fd,
                                  ctx->buf, ctx->buf_len, 0))
            return 0;
    } else {
        if (send(ctx->op_fd, ctx->buf, 0, 0) < 0) {
            PUT_ERROR_ERRNO(ctx->provctx, STM32_R_HASH_FINAL_FAILED,
                            "AF_ALG send (empty message)");
            return 0;
        }
    }

    ctx->buf_len = 0;

    r = recv(ctx->op_fd, out, ctx->digest_len, 0);
    if (r < 0) {
        PUT_ERROR_ERRNO(ctx->provctx, STM32_R_HASH_FINAL_FAILED,
                        "AF_ALG recv failed");
        return 0;
    }
    if ((size_t)r != ctx->digest_len) {
        PUT_ERROR(ctx->provctx, STM32_R_HASH_FINAL_FAILED,
                  "incorrect digest length: got %zd bytes, expected %zu",
                  r, ctx->digest_len);
        return 0;
    }

    *outl = (size_t)r;
    return 1;
}
