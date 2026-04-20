#include <openssl/core_dispatch.h>
#include "digest.h"

extern const OSSL_DISPATCH sha256_functions[];

const OSSL_ALGORITHM stm32_digests[] = {
    { "SHA2-256:SHA-256:SHA256", "provider=stm32", sha256_functions, "SHA-256 via AF_ALG" },
    { NULL, NULL, NULL, NULL }
};
