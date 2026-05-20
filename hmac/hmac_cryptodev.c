#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>

#include <openssl/core.h>
#include <openssl/crypto.h>
#include "hmac.h"
#include "../include/err.h"

#define CRYPTODEV_HMAC_BUF_MAX (256 * 1024)

/*********************************************************************
 *
 * Cryptodev context
 *
 *****/
struct __stm32_hmac_ctx_st__ {
    PROV_CTX *provctx;
    int cfd;
    struct session_op sess;
    int session_opened;
    unsigned int mac_alg;
    const char *alg_name;
    size_t digest_len;
    unsigned char *key_buf;
    size_t key_len;
    unsigned char *buf;
    size_t buf_len;
    size_t buf_max;
};

/*********************************************************************
 *
 * Helpers
 *****/
static unsigned int stm32_cryptodev_hmac_from_name(const char *alg_name)
{
    if (!alg_name) 
        return 0;

    if (strcmp(alg_name, "hmac(sha1)") == 0)
        return CRYPTO_SHA1_HMAC;

    if (strcmp(alg_name, "hmac(sha224)") == 0)
        return CRYPTO_SHA2_224_HMAC;

    if (strcmp(alg_name, "hmac(sha256)") == 0)
        return CRYPTO_SHA2_256_HMAC;

    if (strcmp(alg_name, "hmac(sha384)") == 0)
        return CRYPTO_SHA2_384_HMAC;

    if (strcmp(alg_name, "hmac(sha512)") == 0)
        return CRYPTO_SHA2_512_HMAC;
    
    /* SHA3 not supported by cryptodev */
    return 0;
}