#ifndef ERR_H
#define ERR_H

#include <errno.h>
#include <string.h>
#include <stdint.h>
#include "prov/err.h"  /* libprov : proverr_new_error, proverr_set_error... */
#include "prov.h"

/*********************************************************************
 *
 *  Error reason codes for the STM32 provider
 *
 *****/
enum {
  STM32_R_INIT_FAILED = 1,
  STM32_R_INVALID_ARGUMENT,
  STM32_R_HASH_NEWCTX_FAILED,
  STM32_R_HASH_INIT_FAILED,
  STM32_R_HASH_UPDATE_FAILED,
  STM32_R_HASH_FINAL_FAILED,
  STM32_R_OUTPUT_BUFFER_TOO_SMALL,
  STM32_R_UNSUPPORTED_OPERATION,
  STM32_R_AFALG_FAILED,
};

/*********************************************************************
 *
 * Macro wrapper for regular providers errors. // rely in libprov ERR_raise_data
 *
 *****/
#define PUT_ERROR(pctx, reason, ...)    \
    ERR_raise_data(ERR_HANDLE(pctx), (reason), __VA_ARGS__) 


/*********************************************************************
 *
 * Macro pour lever une erreur avec le message errno courant 
 *
 *****/
#define PUT_ERROR_ERRNO(pctx, reason, what)                         \
    do {                                                            \
        int _saved_errno = errno;                                   \
        PUT_ERROR((pctx), (reason), "%s failed: %s",                \
                  (what), strerror(_saved_errno));                  \
    } while (0)

#endif /* ERR_H */