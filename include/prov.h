#ifndef PROV_H
#define PROV_H

#include<openssl/core_dispatch.h>
#include<openssl/proverr.h>
#include<openssl/core.h>


typedef struct proverr_functions_st PROV_ERR;
struct provider_ctx_st {
    const OSSL_CORE_HANDLE *core_handle;
    PROV_ERR *proverr_handle;
};
typedef struct provider_ctx_st PROV_CTX;

/* Macro to access the error handle (( vigenere ))*/
#define ERR_HANDLE(pctx) ((pctx)->proverr_handle)

/* Functions ctx of provider */
PROV_CTX *provider_ctx_new(const OSSL_CORE_HANDLE *core_handle, 
                           const OSSL_DISPATCH *in);
void provider_ctx_free(PROV_CTX *ctx);

/* Algorithms supported */
extern const OSSL_ALGORITHM stm32_digests[];
//extern const OSSL_ALGORITHM stm32_cipher[];

/* Strings error supported / names coherent with err.c */
extern const OSSL_ITEM stm32_reason_strings[];

#endif /* PROV_H */