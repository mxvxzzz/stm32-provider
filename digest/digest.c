#include <openssl/core_dispatch.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include "digest.h"
#include "../include/names.h"
#include "../include/prov.h"
#include "../include/err.h"


/* prototypes of functions / / static */
static void *digest_newctx(void *provctx, const char *alg_name,
                           size_t digest_size, size_t block_size);
static void digest_freectx(void *vctx);
static int digest_init(void *vctx, const OSSL_PARAM params[]);
static int digest_update(void *vctx, const unsigned char *in, size_t inl);
static int digest_final(void *vctx, unsigned char *out, size_t *outl,
                        size_t outsz);
static int digest_get_params(OSSL_PARAM params[], size_t digest_size,
                             size_t block_size);
static const OSSL_PARAM *digests_gettable_params(void *provctx);

/*********************************************************************
 *
 *  Contexte OpenSSL for digest operation interface
 *
 *****/
struct stm32_digest_ctx_st {
    STM32_HASH_CTX *hash_ctx;
    size_t digest_size;
    size_t block_size;
};

typedef struct stm32_digest_ctx_st STM32_DIGEST_CTX;

/*********************************************************************
 *
 *  Setup
 *
 *****/
static void *digest_newctx(void *provctx, const char *alg_name,
                           size_t digest_size, size_t block_size)
{
    PROV_CTX *pctx = (PROV_CTX *)provctx;
    STM32_DIGEST_CTX *ctx;

    if (pctx == NULL)
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        PUT_ERROR(pctx, STM32_R_HASH_NEWCTX_FAILED,
                  "failed to allocate digest context");
        return NULL;
    }

    ctx->digest_size = digest_size;
    ctx->block_size = block_size;

    ctx->hash_ctx = stm32_hash_newctx(pctx, alg_name, digest_size);
    if (ctx->hash_ctx == NULL) {
        OPENSSL_free(ctx);
        return NULL;
    }

    return ctx;
}

static void digest_freectx(void *vctx)
{
    STM32_DIGEST_CTX *ctx = (STM32_DIGEST_CTX *)vctx;

    if (ctx == NULL)
        return;

    if (ctx->hash_ctx != NULL)
        stm32_hash_freectx(ctx->hash_ctx);

    OPENSSL_free(ctx);
}

static int digest_init(void *vctx, const OSSL_PARAM params[])
{
    STM32_DIGEST_CTX *ctx = (STM32_DIGEST_CTX *)vctx;

    if (ctx == NULL || ctx->hash_ctx == NULL)
        return 0;

    (void)params;
    return stm32_hash_init(ctx->hash_ctx);
}

static int digest_update(void *vctx, const unsigned char *in, size_t inl)
{
    STM32_DIGEST_CTX *ctx = (STM32_DIGEST_CTX *)vctx;

    if (ctx == NULL || ctx->hash_ctx == NULL)
        return 0;

    return stm32_hash_update(ctx->hash_ctx, in, inl);
}

static int digest_final(void *vctx, unsigned char *out, size_t *outl,
                        size_t outsz)
{
    STM32_DIGEST_CTX *ctx = (STM32_DIGEST_CTX *)vctx;

    if (ctx == NULL || ctx->hash_ctx == NULL)
        return 0;

    if (out == NULL || outl == NULL) {
        return 0;
    }

    if (outsz < ctx->digest_size) {
        //proverr_set_error_debug(ctx->provctx, *file, *line, *name_function);   <== libprov / vigenere
        //PUT_ERROR_ERRNO(ctx->provctx, STM32_R_HASH_FINAL_FAILED, "AF_ALG buffer(SHA256) output is < 32"); // 32==> digest_size
        return 0;
    }

    return stm32_hash_final(ctx->hash_ctx, out, outl);
}

/*********************************************************************
 *
 *  Digest functions table for each algorithm supported by the provider
 *
 *****/

// caracteristique algo 
static int digest_get_params(OSSL_PARAM params[], size_t digest_size,
                             size_t block_size)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, block_size))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, digest_size))
        return 0;

    return 1;
}

/* list of params supported */
static const OSSL_PARAM digest_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digests_gettable_params(void *provctx)
{
    (void)provctx;
    return digest_gettable_params;
}

/* Macro helper for defining digest functions to each algorithms supported by the provider */
#define DEFINE_DIGEST(name, alg_str, dsize, bsize)                             \
                                                                               \
    static void *name##_newctx(void *provctx)                                  \
    {                                                                          \
        return digest_newctx(provctx, alg_str, dsize, bsize);                  \
    }                                                                          \
                                                                               \
    static int name##_get_params(OSSL_PARAM params[])                          \
    {                                                                          \
        return digest_get_params(params, dsize, bsize);                        \
    }                                                                          \
                                                                               \
    static const OSSL_DISPATCH name##_functions[] = {                          \
        { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))name##_newctx },            \
        { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))digest_freectx },          \
        { OSSL_FUNC_DIGEST_INIT, (void (*)(void))digest_init },                \
        { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))digest_update },            \
        { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))digest_final },              \
        { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,                                    \
          (void (*)(void))digests_gettable_params },                           \
        { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))name##_get_params },    \
        { 0, NULL }                                                            \
    }

/* Define the digest functions for each supported algorithm */
DEFINE_DIGEST(md5,     "md5",       16,  64);
DEFINE_DIGEST(sha1,     "sha1",     20,  64);
DEFINE_DIGEST(sha224,   "sha224",   28,  64);
DEFINE_DIGEST(sha256,   "sha256",   32,  64);
DEFINE_DIGEST(sha384,   "sha384",   48, 128);
DEFINE_DIGEST(sha512,   "sha512",   64, 128);
#ifdef BACKEND_AFALG
DEFINE_DIGEST(sha3_224, "sha3-224", 28, 144);
DEFINE_DIGEST(sha3_256, "sha3-256", 32, 136);
DEFINE_DIGEST(sha3_384, "sha3-384", 48, 104);
DEFINE_DIGEST(sha3_512, "sha3-512", 64,  72);
#endif
/* Table of supported digest algorithms returned by the provider to the Core OpenSSL */
const OSSL_ALGORITHM stm32_digests[] = {
    { STM32_NAME_MD5,     STM32_PROV_PROPS, md5_functions,
      "STM32 MD5"},
      
    { STM32_NAME_SHA1,     STM32_PROV_PROPS, sha1_functions,
      "STM32 SHA-1"},

    { STM32_NAME_SHA2_224, STM32_PROV_PROPS, sha224_functions,
      "STM32 SHA-224"},

    { STM32_NAME_SHA2_256, STM32_PROV_PROPS, sha256_functions,
      "STM32 SHA-256"},

    { STM32_NAME_SHA2_384, STM32_PROV_PROPS, sha384_functions,
      "STM32 SHA-384"},

    { STM32_NAME_SHA2_512, STM32_PROV_PROPS, sha512_functions,
      "STM32 SHA-512"},

    #ifdef BACKEND_AFALG
    { STM32_NAME_SHA3_224, STM32_PROV_PROPS, sha3_224_functions,
      "STM32 SHA3-224"},

    { STM32_NAME_SHA3_256, STM32_PROV_PROPS, sha3_256_functions,
      "STM32 SHA3-256"},

    { STM32_NAME_SHA3_384, STM32_PROV_PROPS, sha3_384_functions,
      "STM32 SHA3-384"},

    { STM32_NAME_SHA3_512, STM32_PROV_PROPS, sha3_512_functions,
      "STM32 SHA3-512"},
    #endif
    { NULL, NULL, NULL, NULL }
};