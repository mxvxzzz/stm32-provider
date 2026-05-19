#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include "hmac.h"
#include "../include/prov.h"
#include "../include/names.h"
#include "../include/err.h"

/*
 * HMAC provider 
 * 
 * hmac_afalg.c uses alg_name directly 
 * hmac_cryptodev.c mapp alg_name to CRYPTO_SHA*_HMAC constant
 */

/* prototypes of functions */
static void *mac_newctx(void *provctx);
static void mac_freectx(void *vctx);
static void *mac_dupctx(void *vctx);
static int mac_init(void *vctx, const unsigned char *key, size_t keylen,
                        const OSSL_PARAM params[]);
static int mac_update(void *vctx, const unsigned char *in, size_t inl);
static int mac_final(void *vctx, unsigned char *out, size_t *outl,
                        size_t outsize);
static int mac_get_params(OSSL_PARAM params[]);
static const OSSL_PARAM *mac_gettable_params(void *provctx);
static int mac_get_ctx_params(void *vctx, OSSL_PARAM params[]);
static const OSSL_PARAM *mac_gettable_ctx_params(void *vctx, void *provctx);
static int mac_set_ctx_params(void *vctx, const OSSL_PARAM params[]);
static const OSSL_PARAM *mac_settable_ctx_params(void *vctx, void *provctx);

/*********************************************************************
 *
 *  OpenSSL provider MAC context
 *
 *****/
typedef struct {
    void *provctx;
    STM32_HMAC_CTX *hmac_ctx;
    char digest_name[64]; /* OpenSSL name  e.g. "SHA256" */
    char alg_name[80]; /* internal name e.g. "hmac(sha256)" */
    size_t digest_size;
    int digest_set;
    /* key copy for dupctx */
    unsigned char *key;
    size_t keylen;
} STM32_MAC_CTX;

/* Mapping OpenSSL digest name */
typedef struct {
    const char *ossl_name;  /* OSSL_MAC_PARAM_DIGEST */
    const char *alg_name;   
    size_t digest_size;
} HMAC_ALG_MAP;

static const HMAC_ALG_MAP hmac_alg_map[] = {
    { "SHA1",     "hmac(sha1)",   20 },
    { "SHA-1",    "hmac(sha1)",   20 },
    { "SHA256",   "hmac(sha256)", 32 },
    { "SHA-256",  "hmac(sha256)", 32 },
    { "SHA2-256", "hmac(sha256)", 32 },
    { "SHA384",   "hmac(sha384)", 48 },
    { "SHA-384",  "hmac(sha384)", 48 },
    { "SHA2-384", "hmac(sha384)", 48 },
    { "SHA512",   "hmac(sha512)", 64 },
    { "SHA-512",  "hmac(sha512)", 64 },
    { "SHA2-512", "hmac(sha512)", 64 },
#ifdef BACKEND_AFALG
    { "SHA3-224", "hmac(sha3-224)", 28 },
    { "SHA3-256", "hmac(sha3-256)", 32 },
    { "SHA3-384", "hmac(sha3-384)", 48 },
    { "SHA3-512", "hmac(sha3-512)", 64 },
#endif
    { NULL, NULL, 0 }
};

static const HMAC_ALG_MAP *hmac_lookup(const char *ossl_name)
{
    const HMAC_ALG_MAP *m;
    for (m = hmac_alg_map; m->ossl_name != NULL; m++)
        if (OPENSSL_strcasecmp(m->ossl_name, ossl_name) == 0)
            return m;
    return NULL;
}

/*********************************************************************
 *
 *  Setup
 *
 *****/
static void *mac_newctx(void *provctx)
{
    PROV_CTX *pctx = (PROV_CTX *)provctx;
    STM32_MAC_CTX *ctx;

    if (pctx == NULL)
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        PUT_ERROR(pctx, STM32_R_HASH_NEWCTX_FAILED,
                  "failed to allocate MAC context");
        return NULL;
    }

    ctx->provctx = provctx;
    ctx->hmac_ctx = NULL;   /* created in mac_init() once digest is known */
    ctx->digest_set = 0;
    return ctx;
}

static void mac_freectx(void *vctx)
{
    STM32_MAC_CTX *ctx = (STM32_MAC_CTX *)vctx;
    if (ctx == NULL)
        return;
    if (ctx->hmac_ctx)
        stm32_hmac_freectx(ctx->hmac_ctx);
    if (ctx->key) {
        OPENSSL_cleanse(ctx->key, ctx->keylen);
        OPENSSL_free(ctx->key);
    }
    OPENSSL_free(ctx);
}

static void *mac_dupctx(void *vctx)
{
    STM32_MAC_CTX *src = (STM32_MAC_CTX *)vctx;
    STM32_MAC_CTX *dst;

    if (src == NULL)
        return NULL;

    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;

    dst->provctx = src->provctx;
    dst->digest_size = src->digest_size;
    dst->digest_set = src->digest_set;
    OPENSSL_strlcpy(dst->digest_name, src->digest_name, sizeof(dst->digest_name));
    OPENSSL_strlcpy(dst->alg_name, src->alg_name, sizeof(dst->alg_name));

    /* duplicate key */
    if (src->key && src->keylen > 0) {
        dst->key = OPENSSL_memdup(src->key, src->keylen);
        if (!dst->key)
            goto err;
        dst->keylen = src->keylen;
    }

    /* recreate hmac_ctx and reinitialize with the same key */
    if (src->digest_set && src->key) {
        dst->hmac_ctx = stm32_hmac_newctx(dst->provctx, 
                                    dst->alg_name, 
                                    dst->digest_size);
        if (!dst->hmac_ctx)
            goto err;
        if (!stm32_hmac_init(dst->hmac_ctx, dst->key, dst->keylen))
            goto err;
    }

    return dst;

err:
    mac_freectx(dst);
    return NULL;
}

/*********************************************************************
 *
 * init / update / final
 *
 *****/
static int mac_init(void *vctx, const unsigned char *key, size_t keylen,
                    const OSSL_PARAM params[])
{
    STM32_MAC_CTX *ctx = (STM32_MAC_CTX *)vctx;

    if (params != NULL && !mac_set_ctx_params(ctx, params))
        return 0;

    if (!ctx->digest_set) {
        PUT_ERROR((PROV_CTX *)ctx->provctx, STM32_R_INVALID_ARGUMENT,
                  "HMAC digest not set! use OSSL_MAC_PARAM_DIGEST");
        return 0;
    }

    /* store key for dupctx */
    if (key != NULL && keylen > 0) {
        if (ctx->key) {
            OPENSSL_cleanse(ctx->key, ctx->keylen);
            OPENSSL_free(ctx->key);
        }
        ctx->key = OPENSSL_memdup(key, keylen);
        if (!ctx->key)
            return 0;
        ctx->keylen = keylen;
    }

    /* create hmac_ctx if not yet done */
    if (ctx->hmac_ctx == NULL) {
        ctx->hmac_ctx = stm32_hmac_newctx(ctx->provctx,
                                           ctx->alg_name,
                                           ctx->digest_size);
        if (!ctx->hmac_ctx)
            return 0;
    }

    return stm32_hmac_init(ctx->hmac_ctx, ctx->key, ctx->keylen);
}

static int mac_update(void *vctx, const unsigned char *in, size_t inl)
{
    STM32_MAC_CTX *ctx = (STM32_MAC_CTX *)vctx;

    if (!ctx->hmac_ctx) {
        PUT_ERROR((PROV_CTX *)ctx->provctx, STM32_R_HASH_UPDATE_FAILED,
                  "MAC not initialized");
        return 0;
    }
    return stm32_hmac_update(ctx->hmac_ctx, in, inl);
}

static int mac_final(void *vctx, unsigned char *out, size_t *outl,
                     size_t outsize)
{
    STM32_MAC_CTX *ctx = (STM32_MAC_CTX *)vctx;

    if (!ctx->hmac_ctx) {
        PUT_ERROR((PROV_CTX *)ctx->provctx, STM32_R_HASH_FINAL_FAILED,
                  "MAC not initialized");
        return 0;
    }

    if (out == NULL) {
        /* OpenSSL querying size only */
        *outl = ctx->digest_size;
        return 1;
    }

    if (outsize < ctx->digest_size) {
        PUT_ERROR((PROV_CTX *)ctx->provctx, STM32_R_HASH_FINAL_FAILED,
                  "output buffer too small");
        return 0;
    }

    return stm32_hmac_final(ctx->hmac_ctx, out, outl);
}

/*********************************************************************
 *
 * Params
 *
 *****/
static const OSSL_PARAM mac_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *mac_gettable_params(void *provctx)
{
    PROV_CTX *pctx = (PROV_CTX *)provctx;
    if (pctx == NULL)
        return NULL;

    return mac_known_gettable_params;
}

static int mac_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 0))
        return 0;

    return 1;
}

static const OSSL_PARAM mac_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE,        NULL),
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *mac_gettable_ctx_params(void *vctx, void *provctx)
{
    STM32_MAC_CTX *ctx = (STM32_MAC_CTX *)vctx;
    if (ctx == NULL || provctx == NULL)
        return NULL;

    return mac_known_gettable_ctx_params;
}

static int mac_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    STM32_MAC_CTX *ctx = (STM32_MAC_CTX *)vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->digest_size))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->digest_name))
        return 0;

    return 1;
}

static const OSSL_PARAM mac_known_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *mac_settable_ctx_params(void *vctx, void *provctx)
{
    STM32_MAC_CTX *ctx = (STM32_MAC_CTX *)vctx;
    if (ctx == NULL || provctx == NULL)
        return NULL;

    return mac_known_settable_ctx_params;
}

static int mac_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    STM32_MAC_CTX *ctx = (STM32_MAC_CTX *)vctx;
    const OSSL_PARAM *p;
    const HMAC_ALG_MAP *m;
    char digest_buf[64];

    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_DIGEST);
    if (p != NULL) {
        if (p->data == NULL || p->data_size == 0)
            return 0;

        OPENSSL_strlcpy(digest_buf, (const char *)p->data, sizeof(digest_buf));

        m = hmac_lookup(digest_buf);
        if (m == NULL) {
            PUT_ERROR((PROV_CTX *)ctx->provctx,
                      STM32_R_UNSUPPORTED_OPERATION,
                      "unsupported HMAC digest: %s", digest_buf);
            return 0;
        }

        OPENSSL_strlcpy(ctx->digest_name, digest_buf, sizeof(ctx->digest_name));
        OPENSSL_strlcpy(ctx->alg_name, m->alg_name, sizeof(ctx->alg_name));
        ctx->digest_size = m->digest_size;
        ctx->digest_set = 1;

        /* destroy old hmac_ctx if digest changes */
        if (ctx->hmac_ctx) {
            stm32_hmac_freectx(ctx->hmac_ctx);
            ctx->hmac_ctx = NULL;
        }
    }

    return 1;
}

/*********************************************************************
 *
 * Dispatch table
 *
 *****/
static const OSSL_DISPATCH mac_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX,               (void(*)(void))mac_newctx              },
    { OSSL_FUNC_MAC_FREECTX,              (void(*)(void))mac_freectx             },
    { OSSL_FUNC_MAC_DUPCTX,               (void(*)(void))mac_dupctx              },
    { OSSL_FUNC_MAC_INIT,                 (void(*)(void))mac_init                },
    { OSSL_FUNC_MAC_UPDATE,               (void(*)(void))mac_update              },
    { OSSL_FUNC_MAC_FINAL,                (void(*)(void))mac_final               },
    { OSSL_FUNC_MAC_GET_PARAMS,           (void(*)(void))mac_get_params          },
    { OSSL_FUNC_MAC_GETTABLE_PARAMS,      (void(*)(void))mac_gettable_params     },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS,       (void(*)(void))mac_get_ctx_params      },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,  (void(*)(void))mac_gettable_ctx_params },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS,      (void(*)(void))mac_set_ctx_params      },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void(*)(void))mac_settable_ctx_params },
    { 0, NULL }
};

const OSSL_ALGORITHM stm32_macs[] = {
    { STM32_NAME_HMAC, STM32_PROV_PROPS, mac_functions,
      "STM32 HMAC via hardware (afalg/cryptodev)" },
    { NULL, NULL, NULL, NULL }
};