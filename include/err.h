#ifndef ERR_H
#define ERR_H
#include <stdint.h>
#include "prov/err.h"  /* libprov : proverr_new_error, proverr_set_error... */
#include "prov.h"

enum {
  STM32_R_INIT_FAILED = 1,
  STM32_R_INVALID_ARGUMENT,
  STM32_R_BACKEND_SELECTION_FAILED,
  STM32_R_BACKEND_INIT_FAILED,
  STM32_R_HASH_NEWCTX_FAILED,
  STM32_R_HASH_INIT_FAILED,
  STM32_R_HASH_UPDATE_FAILED,
  STM32_R_HASH_FINAL_FAILED,
  STM32_R_OUTPUT_BUFFER_TOO_SMALL,
  STM32_R_UNSUPPORTED_OPERATION,
  STM32_R_AFALG_FAILED,
};

/* Macro to raise an error in the provider with a custom message. // already defined in libprov / vigenere
 * ex: PUT_ERROR(ctx->provctx, STM32_R_HASH_INIT_FAILED, NULL)
 * ex: PUT_ERROR(ctx->provctx, STM32_R_INVALID_ARGUMENT,
 *               "taille=%zu", size)
 */
#define PUT_ERROR(pctx, reason, fmt, ...)                           \
    do {                                                            \
        proverr_new_error(ERR_HANDLE(pctx));                        \
        proverr_set_error_debug(ERR_HANDLE(pctx),                   \
                                __FILE__, __LINE__, __func__);      \
        proverr_set_error(ERR_HANDLE(pctx), (reason), (fmt),       \
                          ##__VA_ARGS__);                           \
    } while (0)

/* macro pour lever une erreur avec le message errno courant */
#define PUT_ERROR_ERRNO(pctx, reason, what)                         \
    do {                                                            \
        int _saved_errno = errno;                                   \
        PUT_ERROR((pctx), (reason), "%s failed: %s",                \
                  (what), strerror(_saved_errno));                  \
    } while (0)


/*
void stm32_put_error(const PROV_CTX *ctx, uint32_t reason,
                     const char *file, int line, const char *func,
                     const char *fmt, ...);

// helper like OSSL_FUNC_*  
#define PUT_ERROR(ctx, reason, fmt, ...)                                        \
  stm32_put_error((ctx), (reason), __FILE__, __LINE__, __func__, (fmt),         \
                  ##__VA_ARGS__)
*/
#endif /* ERR_H */