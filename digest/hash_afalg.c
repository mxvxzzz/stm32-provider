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


/* prototypes of functions / / static */
static void  stm32_afalg_close_fd(int *fd);
static int stm32_afalg_open_tfm(PROV_CTX *provctx, const char *alg_name);
static int stm32_afalg_open_op(PROV_CTX *provctx, int tf_fd);
static int stm32_afalg_send_all(PROV_CTX *provctx, int fd,
                                const unsigned char *buf, size_t len);
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
    size_t digest_size;  
};

/*********************************************************************
 *
 *  Helpers functions for AF_ALG inerfacing
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
                                const unsigned char *buf, size_t len)
{
    size_t off = 0;
    ssize_t written;

    while (off < len) {
        written = write(fd, buf + off, len - off);
        if (written < 0) {
            PUT_ERROR_ERRNO(provctx, STM32_R_HASH_UPDATE_FAILED, "AF_ALG write");
            return 0;
        }
        if (written == 0) {
            PUT_ERROR(provctx, STM32_R_HASH_UPDATE_FAILED,
                      "short write on AF_ALG socket");
            return 0;
        }
        off += (size_t)written;
    }

    return 1;
}


/*********************************************************************
 *
 *  Setup
 *
 *****/
void *stm32_hash_newctx(void *vprovctx, const char *alg_name,
                                  size_t digest_size)
{
    PROV_CTX *provctx = (PROV_CTX *)vprovctx;
    STM32_HASH_CTX *ctx;

    if (provctx == NULL)
        return NULL;

    if (alg_name == NULL || digest_size == 0) {
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

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL){
        return NULL;
    }

    ctx->provctx = provctx;
    ctx->tf_fd = -1;
    ctx->op_fd = -1;
    ctx->digest_size = digest_size;
    ctx->alg_name = alg_name;

    ctx->tf_fd = stm32_afalg_open_tfm(provctx, alg_name);
    if (ctx->tf_fd < 0) {
        //PUT_ERROR_ERRNO(ctx->provctx, STM32_R_HASH_NEWCTX_FAILED, "AF_ALG socket failed");
        OPENSSL_free(ctx);
        return NULL;
    }
    return ctx;
}

/* signature ok(core_dipatch exigence) donc cast */
void stm32_hash_freectx(STM32_HASH_CTX *ctx)
{
    if (ctx == NULL)
        return;

    stm32_afalg_close_fd(&ctx->op_fd);
    stm32_afalg_close_fd(&ctx->tf_fd);
    OPENSSL_free(ctx);
}


static int stm32_hash_init(void ctx)
{
    if (ctx == NULL)
        return 0;

    if (ctx->op_fd >= 0){
        PUT_ERROR(ctx->provctx, STM32_R_HASH_INIT_FAILED,
                  "invalid AF_ALG transform socket");
        close(ctx->op_fd);
        ctx->op_fd = -1;
    }

    stm32_afalg_close_fd(&ctx->op_fd);

    ctx->op_fd = stm32_afalg_open_op(ctx->provctx, ctx->tf_fd);
    if (ctx->op_fd < 0) {
        PUT_ERROR_ERRNO(ctx->provctx, STM32_R_HASH_INIT_FAILED, "AF_ALG accept failed");
        return 0;
    }
    (void)params;
    return 1;
}

int stm32_hash_update(void *ctx, const unsigned char *in, size_t inl)
{
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

    return stm32_afalg_send_all(ctx->provctx, ctx->op_fd, in, inl);
}

int stm32_hash_final(void *vctx, unsigned char *out, size_t *outl)
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

    ssize_t r = read(ctx->op_fd, out, ctx->digest_len);
    if (r < 0){
        PUT_ERROR_ERRNO(ctx->provctx, STM32_R_HASH_FINAL_FAILED, "AF_ALG read failed");
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