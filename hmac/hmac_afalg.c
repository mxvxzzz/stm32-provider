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
