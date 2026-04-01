#include<openssl/core.h>
#include<openssl/core_dispatch.h>
#include<openssl/core_names.h>
#include<openssl/params.h>

/* ctx provider*/
struct stm32_prov_ctx_st{
    const OSSL_CORE_HANDLE *handle;
};

typedef struct stm32_prov_ctx_st STM32_PROV_CTX;

static STM32_PROV_CTX *stm32_ctx_new(const OSSL_CORE_HANDLE *handle)
{
    /* data */
    STM32_PROV_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) return NULL;
    ctx -> handle = handle;
    return ctx;
}

static void stm32_ctx_free(STM32_PROV_CTX *ctx)
{
    OPENSSL_free(ctx);
}


/* param de provider*/
static const OSSL_PARAM stm32_param_types[] = 
{
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *stm32_gettable_params(void *provctx)
{
    (void)provctx;
    return stm32_param_types;
}
static int stm32_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    (void)provctx;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "STM32 Provider"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "0.1.0"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;

    return 1;
}

/* query */
static const OSSL_ALGORITHM *stm32_query(void *provctx, int operation_id, int *no_cache)
{
    (void)provctx;
    *no_cache = 0;

    switch (operation_id){
        /* chaque algo implémenté : branche ici
         * case OSSL_OP_DIGEST : return stm32_digest
         * case OSSL_OP_CIPHER : return stm32_cipher
        */
        default :
            break;
    }
    // si pas trouvé (provider ne supporte pas cet algo)
    // ========== > default ou fips provider : priorité a configurer dans openssl.cnf
    return NULL;
}

/* teardown / dlclose()*/
static void stm32_teardown(void *provctx)
{
    stm32_ctx_free((STM32_PROV_CTX *) provctx);
}

/* dispatch table*/

static const OSSL_DISPATCH stm32_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN,
      (void (*)(void))stm32_teardown        },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
      (void (*)(void))stm32_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,
      (void (*)(void))stm32_get_params      },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,
      (void (*)(void))stm32_query           },
    { 0, NULL }
};

/* Entry point avec openssl core */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH    *in,
                       const OSSL_DISPATCH   **out,
                       void                  **provctx)
{
     
    /* pour l'instant on n'en a pas besoin
    */
   // (void)in;
    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        default:
            break;
        }
    }

    *provctx = stm32_ctx_new(handle);
    if (*provctx == NULL)
        return 0;

    /* return dispatch table a OpenSSL */
    *out = stm32_dispatch_table;
    return 1;
}
