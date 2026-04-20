#include <openssl/core.h>
#include <openssl/proverr.h>
#include "include/err.h"
#include "include/prov.h"

/* Tableau global des messages d'erreur du provider ST.
 * PROV_R_* : codes standard OpenSSL pour les algos connus
 * STM32_R_* : codes custom définis dans err.h
 */
const OSSL_ITEM stm32_reason_strings[] = {
    /* digest */
    { PROV_R_DIGEST_NOT_ALLOWED,      "digest not allowed"      },
    { PROV_R_INVALID_DIGEST,          "invalid digest"          },
    { PROV_R_INVALID_DIGEST_LENGTH,   "incorrect digest length" },
    { PROV_R_INVALID_DIGEST_SIZE,     "incorrect digest size"   },
    { PROV_R_INVALID_X931_DIGEST,     "invalid x931 digest"     },
    { PROV_R_MISSING_MESSAGE_DIGEST,  "missing message digest"  },
    { PROV_R_XOF_DIGESTS_NOT_ALLOWED, "xof digest not allowed"  },
    /* ST custom */
    { STM32_R_HASH_INIT_FAILED,       "hash init failed"        },
    { STM32_R_HASH_UPDATE_FAILED,     "hash update failed"      },
    { STM32_R_HASH_FINAL_FAILED,      "hash final failed"       },
    { STM32_R_HASH_NEWCTX_FAILED,     "hash newctx failed"      },
    { STM32_R_BACKEND_INIT_FAILED,    "backend init failed"     },
    { STM32_R_INVALID_ARGUMENT,       "invalid argument"        },
    { STM32_R_OUTPUT_BUFFER_TOO_SMALL,"output buffer too small" },
    { STM32_R_UNSUPPORTED_OPERATION,  "unsupported operation"   },
    /* cipher — à ajouter plus tard */
    { 0, NULL }
};