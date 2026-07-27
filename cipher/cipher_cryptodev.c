#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>

#include <openssl/core.h>
#include <openssl/crypto.h>

#include "cipher.h"
#include "../include/prov.h"
#include "../include/err.h"

static void cdev_close_session(STM32_CIPHER_HW_CTX *ctx);
static int cdev_open_session(STM32_CIPHER_HW_CTX *ctx);
static void ctr_increment_iv(unsigned char iv[16], size_t bytes_processed);
typedef struct {
    STM32_CIPHER_MODE mode;
    size_t            keylen;
    unsigned int      cryptodev_id;
} CIPHER_MAP;

static unsigned int cipher_map_lookup(STM32_CIPHER_MODE mode, size_t keylen);

static const CIPHER_MAP cipher_map[] = {
    { STM32_CIPHER_MODE_ECB, 16, CRYPTO_AES_ECB },
    { STM32_CIPHER_MODE_ECB, 24, CRYPTO_AES_ECB },
    { STM32_CIPHER_MODE_ECB, 32, CRYPTO_AES_ECB },
    { STM32_CIPHER_MODE_CBC, 16, CRYPTO_AES_CBC },
    { STM32_CIPHER_MODE_CBC, 24, CRYPTO_AES_CBC },
    { STM32_CIPHER_MODE_CBC, 32, CRYPTO_AES_CBC },
    { STM32_CIPHER_MODE_CTR, 16, CRYPTO_AES_CTR },
    { STM32_CIPHER_MODE_CTR, 24, CRYPTO_AES_CTR },
    { STM32_CIPHER_MODE_CTR, 32, CRYPTO_AES_CTR },
    { 0, 0, 0 }
};

static unsigned int cipher_map_lookup(STM32_CIPHER_MODE mode, size_t keylen)
{
    const CIPHER_MAP *m;

    for (m = cipher_map; m->cryptodev_id != 0; m++) {
        if (m->mode == mode && m->keylen == keylen)
            return m->cryptodev_id;
    }
    return 0;
}

/*********************************************************************
 *
 *  Context cryptodev
 *
 *****/
struct __stm32_cipher_hw_ctx_st__ {
    PROV_CTX          *provctx;
    int                cfd;
    struct session_op  sess;
    int                session_open;
    STM32_CIPHER_MODE  mode;
    size_t             keylen;
    int                encrypt;
    unsigned char      iv[16];
    size_t             ivlen;
    unsigned char      key[32];
};

static void cdev_close_session(STM32_CIPHER_HW_CTX *ctx)
{
    if (ctx->cfd >= 0 && ctx->session_open) {
        ioctl(ctx->cfd, CIOCFSESSION, &ctx->sess.ses);
        ctx->session_open = 0;
    }
}

static int cdev_open_session(STM32_CIPHER_HW_CTX *ctx)
{
    memset(&ctx->sess, 0, sizeof(ctx->sess));
    ctx->sess.cipher  = cipher_map_lookup(ctx->mode, ctx->keylen);
    ctx->sess.keylen  = (uint32_t)ctx->keylen;
    ctx->sess.key     = ctx->key;

    if (ctx->sess.cipher == 0) {
        PUT_ERROR(ctx->provctx, STM32_R_UNSUPPORTED_OPERATION,
                  "cryptodev: unsupported AES mode/keylen combination");
        return 0;
    }

    if (ioctl(ctx->cfd, CIOCGSESSION, &ctx->sess) < 0) {
        PUT_ERROR_ERRNO(ctx->provctx, STM32_R_CIPHER_INIT_FAILED,
                        "cryptodev CIOCGSESSION");
        return 0;
    }

    ctx->session_open = 1;
    return 1;
}

static void ctr_increment_iv(unsigned char iv[16], size_t bytes_processed)
{
    size_t  blocks = bytes_processed / 16;
    int     i;
    unsigned int carry;

    /* Add 'blocks' to the 128-bit big-endian counter */
    carry = (unsigned int)blocks;
    for (i = 15; i >= 0 && carry != 0; i--) {
        carry += iv[i];
        iv[i]  = (unsigned char)(carry & 0xFF);
        carry >>= 8;
    }
}

/*********************************************************************
 *
 *  Setup
 *
 *****/
STM32_CIPHER_HW_CTX *stm32_cipher_newctx(void *vprovctx,
                                          const char *alg_name,
                                          STM32_CIPHER_MODE mode,
                                          size_t keylen)
{
    PROV_CTX            *pctx = (PROV_CTX *)vprovctx;
    STM32_CIPHER_HW_CTX *ctx;

    (void)alg_name;

    if (pctx == NULL || keylen == 0) {
        PUT_ERROR(pctx, STM32_R_INVALID_ARGUMENT,
                  "invalid cryptodev cipher newctx arguments");
        return NULL;
    }

    if (cipher_map_lookup(mode, keylen) == 0) {
        PUT_ERROR(pctx, STM32_R_UNSUPPORTED_OPERATION,
                  "cryptodev: unsupported AES mode/keylen");
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        PUT_ERROR(pctx, STM32_R_CIPHER_NEWCTX_FAILED,
                  "failed to allocate cryptodev cipher context");
        return NULL;
    }

    ctx->provctx      = pctx;
    ctx->cfd          = -1;
    ctx->session_open = 0;
    ctx->mode         = mode;
    ctx->keylen       = keylen;
    ctx->ivlen        = (mode == STM32_CIPHER_MODE_ECB) ? 0 : 16;

    ctx->cfd = open("/dev/crypto", O_RDWR, 0);
    if (ctx->cfd < 0) {
        PUT_ERROR_ERRNO(pctx, STM32_R_CIPHER_NEWCTX_FAILED,
                        "open /dev/crypto");
        OPENSSL_free(ctx);
        return NULL;
    }
    return ctx;
}

void stm32_cipher_freectx(STM32_CIPHER_HW_CTX *ctx)
{
    if (ctx == NULL)
        return;
    cdev_close_session(ctx);
    if (ctx->cfd >= 0) {
        close(ctx->cfd);
        ctx->cfd = -1;
    }
    OPENSSL_cleanse(ctx->key, sizeof(ctx->key));
    OPENSSL_free(ctx);
}

int stm32_cipher_init(STM32_CIPHER_HW_CTX *ctx,
                      const unsigned char *key, size_t keylen,
                      const unsigned char *iv,  size_t ivlen,
                      int encrypt)
{
    if (ctx == NULL || ctx->cfd < 0) {
        PUT_ERROR(ctx->provctx, STM32_R_CIPHER_INIT_FAILED,
                  "invalid cryptodev cipher fd");
        return 0;
    }

    cdev_close_session(ctx);

    memcpy(ctx->key, key, keylen);
    ctx->encrypt = encrypt;

    if (iv != NULL && ivlen > 0)
        memcpy(ctx->iv, iv, ivlen);
    else
        memset(ctx->iv, 0, sizeof(ctx->iv));

    return cdev_open_session(ctx);
}

int stm32_cipher_update(STM32_CIPHER_HW_CTX *ctx,
                        unsigned char *out, size_t *outl,
                        const unsigned char *in, size_t inl)
{
    struct crypt_op  cop;
    unsigned char    saved_iv[16];

    if (ctx == NULL || !ctx->session_open) {
        PUT_ERROR(ctx->provctx, STM32_R_CIPHER_UPDATE_FAILED,
                  "cryptodev cipher session not open");
        return 0;
    }

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (ctx->mode == STM32_CIPHER_MODE_CBC && !ctx->encrypt && inl >= 16)
        memcpy(saved_iv, in + inl - 16, 16);

    memset(&cop, 0, sizeof(cop));
    cop.ses = ctx->sess.ses;
    cop.op  = ctx->encrypt ? COP_ENCRYPT : COP_DECRYPT;
    /* force kernel copy memory-pages (NO ZERO COPY)
    if (ctx->mode != STM32_CIPHER_MODE_CTR)
	cop.flags = COP_FLAG_NO_ZC; 	
     */
    cop.len = (uint32_t)inl;
    cop.src = (unsigned char *)in;
    cop.dst = out;
    cop.iv  = (ctx->ivlen > 0) ? ctx->iv : NULL;

    if (ioctl(ctx->cfd, CIOCCRYPT, &cop) < 0) {
        PUT_ERROR_ERRNO(ctx->provctx, STM32_R_CIPHER_UPDATE_FAILED,
                        "cryptodev CIOCCRYPT");
        return 0;
    }

    /* IV chaining for the future call */
    if (ctx->mode == STM32_CIPHER_MODE_CBC && inl >= 16) {
        if (ctx->encrypt)
            memcpy(ctx->iv, out + inl - 16, 16);
        else
            memcpy(ctx->iv, saved_iv, 16);
    }

   /* Fix CTR: Cryptodev restarts from the initial counter
      on each CIOCCRYPT call. as solution is to manually
      increment the counter after each ioctl call.
    */
    if (ctx->mode == STM32_CIPHER_MODE_CTR)
        ctr_increment_iv(ctx->iv, inl);

    *outl = inl;
    return 1;
}

int stm32_cipher_final(STM32_CIPHER_HW_CTX *ctx,
                       unsigned char *out, size_t *outl)
{
    (void)ctx;
    (void)out;
    *outl = 0;
    return 1;
}
