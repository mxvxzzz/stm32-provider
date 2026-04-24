#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "include/prov.h"
#include "include/err.h"   // libprov — proverr_new_handle, proverr_free_handle

/* forward declarations with types OSSL_FUNC_**/
static OSSL_FUNC_provider_gettable_params_fn prov_gettable_params;
static OSSL_FUNC_provider_get_params_fn prov_get_params;
static OSSL_FUNC_provider_query_operation_fn prov_query;
static OSSL_FUNC_provider_unquery_operation_fn prov_unquery;
static OSSL_FUNC_provider_get_reason_strings_fn prov_get_reason_strings_disptach;
static OSSL_FUNC_provider_get_capabilities_fn prov_get_capabilities;
static OSSL_FUNC_provider_self_test_fn prov_self_test;

/*********************************************************************
 *
 *  The implementation 
 *
 *****/

/*********************************************************************
 * 
 * Parameter names that core passes to providers 
 * All the OSSL__* types come from <openssl/core_names.h>
 *
 *****/

static const OSSL_PARAM prov_param_types[] = 
{
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *prov_gettable_params(void *provctx)
{
    (void)provctx;
    return prov_param_types;
}
static int prov_get_params(void *provctx, OSSL_PARAM params[])
{
    (void)provctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "STM32 Provider"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "1.0.0"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "STM32 provider build 1.0.0"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;

    return 1;
}

/*********************************************************************
 *
 *  Setup
 *
 *****/

/* query */
static const OSSL_ALGORITHM *prov_query(void *provctx, int operation_id, int *no_cache)
{
    (void)provctx;
    *no_cache = 0;

    switch (operation_id){
        case OSSL_OP_DIGEST : 
            return stm32_digests;
        /* 
        case OSSL_OP_CIPHER : 
            return stm32_cipher
        */
        default :
            break;
    }
    return NULL;
}
/* teardown / dlclose() */
static void prov_teardown(void *provctx)
{
    provider_ctx_free((PROV_CTX *) provctx);
}
/* unquery operations */
static void prov_unquery(void *provctx, int operation_id,
                        const OSSL_ALGORITHM *algs)
{
    (void)provctx;
    (void)operation_id;
    (void)algs;
}


static const OSSL_ITEM *prov_get_reason_strings_disptach(void *provctx)
{
    (void) provctx;
    return stm32_reason_strings;
}
/* cpabalities of provider to the Core*/
int prov_get_capabilities(void *provctx, const char *capability,
                              OSSL_CALLBACK *cb, void *arg)
{
    (void)provctx;
    (void)capability;
    (void)cb;
    (void)arg;
    return 0;
}
static int prov_self_test(void *provctx)
{
    (void)provctx;
    return 1;
}

/* dispatch table of provider to Core */
static const OSSL_DISPATCH prov_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))prov_teardown},
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))prov_gettable_params},
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))prov_get_params},
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))prov_query},
    { OSSL_FUNC_PROVIDER_UNQUERY_OPERATION, (void (*)(void))prov_unquery},
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (void (*)(void))prov_get_reason_strings_disptach},
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))prov_get_capabilities},
    { OSSL_FUNC_PROVIDER_SELF_TEST, (void (*)(void))prov_self_test},
    { 0, NULL }
};

/*********************************************************************
 *
 *  Provider context
 *
 *****/
/* provider_ctx_new is public in prov.h */
PROV_CTX *provider_ctx_new(const OSSL_CORE_HANDLE *core_handle, const OSSL_DISPATCH *in)
{
    PROV_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) 
        return NULL;
    ctx -> core_handle = core_handle;
    ctx->proverr_handle = proverr_new_handle(core_handle, in);
    if (ctx->proverr_handle == NULL) {
        OPENSSL_free(ctx);
        return NULL;
    }
    return ctx;
}

void provider_ctx_free(PROV_CTX *ctx)
{
    if (ctx == NULL)
        return;
    proverr_free_handle(ctx->proverr_handle);
    OPENSSL_free(ctx);
}

/* Entry point openssl core */
int OSSL_provider_init(const OSSL_CORE_HANDLE *core_handle,
                       const OSSL_DISPATCH    *in,
                       const OSSL_DISPATCH   **out,
                       void                  **provctx)
{    
    (void)in;

    *provctx = provider_ctx_new(core_handle, in);
    if (*provctx == NULL)
        return 0;

    /* return dispatch table for OpenSSL */
    *out = prov_dispatch_table;
    return 1;
}
