#include <openssl/core.h>
#include <openssl/proverr.h>
#include "prov.h"
/*
static const OSSL_ITEM reason_strings_dispatch[] = {
    { VIGENERE_NO_KEYLEN_SET, "no key length has been set" },
    { VIGENERE_ONGOING_OPERATION, "an operation is underway" },
    { VIGENERE_INCORRECT_KEYLEN, "incorrect key length" },
    { 0, NULL }
};
*/
const OSSL_ITEM reason_strings_dispatch_digest[] = {
    { PROV_R_DIGEST_NOT_ALLOWED, " " },
    { PROV_R_INVALID_DIGEST, "" },
    { PROV_R_INVALID_DIGEST_LENGTH, "incorrect digest length" },
    { PROV_R_INVALID_DIGEST_SIZE, "incorrect digest size"},
    { PROV_R_INVALID_X931_DIGEST, " "},
    { PROV_R_MISSING_MESSAGE_DIGEST, " "},
    { PROV_R_XOF_DIGESTS_NOT_ALLOWED, " "},
    { 0, NULL }
};

/* Codes d'erreur provider by me
 * j'ai trouvé libprov wrapper des erreurs de providers qui vient de core openssl 
 * je doit chercher a ce point laquelle et comment je vais mapper les erreurs 
*/
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
  STM32_R_UNSUPPORTED_OPERATION
};

const OSSL_ITEM *get_reason_strings(void);

void stm32_put_error(const PROV_CTX *ctx, uint32_t reason,
                     const char *file, int line, const char *func,
                     const char *fmt, ...);

/* helper like OSSL_FUNC_*   */                    
#define PUT_ERROR(ctx, reason, fmt, ...)                                        \
  stm32_put_error((ctx), (reason), __FILE__, __LINE__, __func__, (fmt),         \
                  ##__VA_ARGS__)
