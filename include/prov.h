#ifndef PROV_H
#define PROV_H

#include<openssl/core_dispatch.h>
#include<openssl/proverr.h>
#include<openssl/core.h>


struct proverr_functions_st{
    const OSSL_CORE_HANDLE *core_handle;
    OSSL_FUNC_core_new_error_fn *core_new_error;
    OSSL_FUNC_core_set_error_debug_fn *core_set_error_fn;
    OSSL_FUNC_core_vset_error_fn *core_vset_error_fn;
};

struct provider_ctx_st {
    const OSSL_CORE_HANDLE *core_handle;
};

typedef struct provider_ctx_st PROV_CTX;

/* 
 * Functions ctx
 *
 */

PROV_CTX *provider_ctx_new(const OSSL_CORE_HANDLE *core_handle);

void provider_ctx_free(PROV_CTX *ctx);



//struct provider_err_funcs {}

/*
 *  table of algo supported
*/

extern const OSSL_ALGORITHM stm32_digests[];
extern const OSSL_ITEM reason_strings_dispatch_digest[];

//extern const OSSL_ALGORITHM stm32_cipher[];


#endif /* PROV_H */