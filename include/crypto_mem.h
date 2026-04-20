#ifndef CRYPTO_MEM_H
#define CRYPTO_MEM_H

/*
 * Forward declarations to ensure we get signatures right.  All the
 * OSSL_FUNC_* types come from <openssl/core_dispatch.h>
 */

#include <openssl/core_dispatch.h>

static OSSL_FUNC_CRYPTO_malloc_fn *CRYPTO_malloc;
static OSSL_FUNC_CRYPTO_zalloc_fn *CRYPTO_zalloc;
static OSSL_FUNC_CRYPTO_realloc_fn *c_CRYPTO_realloc;
static OSSL_FUNC_CRYPTO_clear_realloc_fn *c_CRYPTO_clear_realloc;
static OSSL_FUNC_CRYPTO_free_fn *CRYPTO_free;
static OSSL_FUNC_CRYPTO_clear_free_fn *CRYPTO_clear_free;





static OSSL_FUNC_provider_query_operation_fn cipher_prov_operation;
static OSSL_FUNC_provider_get_params_fn cipher_prov_get_params;
static OSSL_FUNC_provider_get_reason_strings_fn cipher_prov_get_reason_strings;

static OSSL_FUNC_cipher_newctx_fn cipher_newctx;
static OSSL_FUNC_cipher_encrypt_init_fn _encrypt_init;
static OSSL_FUNC_cipher_decrypt_init_fn cipher_decrypt_init;
static OSSL_FUNC_cipher_update_fn cipher_update;
static OSSL_FUNC_cipher_final_fn cipher_final;
static OSSL_FUNC_cipher_dupctx_fn cipher_dupctx;
static OSSL_FUNC_cipher_freectx_fn cipher_freectx;
static OSSL_FUNC_cipher_get_params_fn cipher_get_params;
static OSSL_FUNC_cipher_gettable_params_fn cipher_gettable_params;
static OSSL_FUNC_cipher_set_ctx_params_fn cipher_set_ctx_params;
static OSSL_FUNC_cipher_get_ctx_params_fn cipher_get_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn cipher_settable_ctx_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn cipher_gettable_ctx_params;

#endif /* CRYPTO_MEM_H */