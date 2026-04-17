#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <linux/if_alg.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "digest.h"

/* kernel dasn if_alg.h
struct sockaddr_alg {
    __u16   salg_family;    
    __u8    salg_type[14];  
    __u32   salg_feat;
    __u32   salg_mask;
    __u8    salg_name[64];  
};
*/
/* standard c99*/
struct sockaddr_alg {
    uint16_t salg_family;   
    uint8_t  salg_type[14]; 
    uint32_t salg_feat;     
    uint32_t salg_mask;
    uint8_t  salg_name[64];
};

struct stm32_sha256_ctx_st {
    int tf_fd;   
    int op_fd;   
};

typedef struct stm32_sha256_ctx_st STM32_SHA256_CTX;

static void *sha256_newctx(void *provctx)
{
    STM32_SHA256_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->tf_fd = -1;
    ctx->op_fd = -1;

    ctx->tf_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (ctx->tf_fd < 0) {
        OPENSSL_free(ctx);
        return NULL;
    }

    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type   = "hash",
        .salg_name   = "sha256"
    };

    if (bind(ctx->tf_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(ctx->tf_fd);
        OPENSSL_free(ctx);
        return NULL;
    }

    /* op_fd sera cree dans init()
    ctx->op_fd = accept(ctx->tf_fd, NULL, NULL);
    if (ctx->op_fd < 0) {
        close(ctx->tf_fd);
        OPENSSL_free(ctx);
        return NULL;
    }*/

    (void)provctx;
    return ctx;
}

/* signature ok(core_dipatch exigence) donc cast */
static void sha256_freectx(void *vctx)
{
    STM32_SHA256_CTX *ctx = (STM32_SHA256_CTX *)vctx; /*cast */

    if (ctx == NULL)
        return NULL;

    if (ctx->op_fd >= 0)
        close(ctx->op_fd);

    if (ctx->tf_fd >= 0)
        close(ctx->tf_fd);

    OPENSSL_free(ctx);
}


static int sha256_init(void *vctx, const OSSL_PARAM params[])
{
    STM32_SHA256_CTX *ctx = (STM32_SHA256_CTX *)vctx;
    if (ctx == NULL)
        return 0;

    if (ctx->op_fd >= 0){
        close(ctx->op_fd);
        ctx->op_fd = -1;
    }

    ctx->op_fd = accept(ctx->tf_fd, NULL, NULL);
    if (ctx->op_fd < 0) {
        return 0;
    }
    (void)params;
    return 1;
}

static int sha256_update(void *vctx, const unsigned char *in, size_t inl)
{
    STM32_SHA256_CTX *ctx = (STM32_SHA256_CTX *)vctx;
    if (ctx == NULL)
        return 0;

    if (write(ctx->op_fd, in, inl) < 0)
        return 0;
    return 1;
}

static int sha256_final(void *vctx, unsigned char *out, size_t *outl, size_t outsz)
{
    STM32_SHA256_CTX *ctx = (STM32_SHA256_CTX *)vctx;
    if (ctx == NULL)
        return 0;

    if (outsz < 32) 
        return 0;
    ssize_t r = read(ctx->op_fd, out, 32);
    if (r < 0){
        return 0;
    }
    *outl = r;
    return 1;
}

// caracteristique algo 
static int sha256_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 64))
        return 0;
    
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !(OSSL_PARAM_set_size_t(p, 32)))
        return 0;
    
    return 1;
}


static const OSSL_DISPATCH sha256_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,
        (void (*)(void))sha256_newctx    },
    { OSSL_FUNC_DIGEST_FREECTX,
        (void (*)(void))sha256_freectx   },
    { OSSL_FUNC_DIGEST_INIT,
        (void (*)(void))sha256_init      },
    { OSSL_FUNC_DIGEST_UPDATE,
        (void (*)(void))sha256_update    },
    { OSSL_FUNC_DIGEST_FINAL,
        (void (*)(void))sha256_final     },
    { OSSL_FUNC_DIGEST_GET_PARAMS,
        (void (*)(void))sha256_get_params},
    { 0, NULL }
};

