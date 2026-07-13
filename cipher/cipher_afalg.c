#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

#include <openssl/core.h>
#include <openssl/crypto.h>

#include "cipher.h"
#include "../include/prov.h"
#include "../include/err.h"

static void afalg_close_fd(int *fd);
static int  afalg_open_tfm(PROV_CTX *pctx, const char *alg_name);
static int  afalg_set_key(PROV_CTX *pctx, int tf_fd,
                          const unsigned char *key, size_t keylen);
static int  afalg_open_op(PROV_CTX *pctx, int tf_fd);
static int  afalg_send_first(PROV_CTX *pctx, int op_fd,
                             int encrypt,
                             const unsigned char *iv, size_t ivlen,
                             const unsigned char *in, size_t inl,
                             int more);
static int  afalg_send_more(PROV_CTX *pctx, int op_fd,
                            const unsigned char *in, size_t inl,
                            int more);
static int  afalg_recv(PROV_CTX *pctx, int op_fd,
                       unsigned char *out, size_t len);

/*********************************************************************
 *
 *  Contexte AF_ALG
 *
 *****/
struct __stm32_cipher_hw_ctx_st__ {
    PROV_CTX          *provctx;
    int                tf_fd;       
    int                op_fd;      
    STM32_CIPHER_MODE  mode;
    size_t             ivlen;
    int                first_send;  
    int                encrypt;
    unsigned char      iv[16];
};

/*********************************************************************
 *
 *  Helpers 
 *
 *****/
static void afalg_close_fd(int *fd)
{
    if (fd != NULL && *fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

static int afalg_open_tfm(PROV_CTX *pctx, const char *alg_name)
{
    struct sockaddr_alg sa;
    int tf_fd;

    tf_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (tf_fd < 0) {
        PUT_ERROR_ERRNO(pctx, STM32_R_CIPHER_NEWCTX_FAILED,
                        "AF_ALG cipher socket");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    OPENSSL_strlcpy((char *)sa.salg_type, "skcipher", sizeof(sa.salg_type));
    OPENSSL_strlcpy((char *)sa.salg_name, alg_name,   sizeof(sa.salg_name));

    if (bind(tf_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        PUT_ERROR_ERRNO(pctx, STM32_R_CIPHER_NEWCTX_FAILED,
                        "AF_ALG cipher bind");
        close(tf_fd);
        return -1;
    }
    return tf_fd;
}

static int afalg_set_key(PROV_CTX *pctx, int tf_fd,
                         const unsigned char *key, size_t keylen)
{
    if (setsockopt(tf_fd, SOL_ALG, ALG_SET_KEY,
                   key, (socklen_t)keylen) < 0) {
        PUT_ERROR_ERRNO(pctx, STM32_R_CIPHER_INIT_FAILED,
                        "AF_ALG cipher ALG_SET_KEY");
        return 0;
    }
    return 1;
}

static int afalg_open_op(PROV_CTX *pctx, int tf_fd)
{
    int op_fd = accept(tf_fd, NULL, NULL);
    if (op_fd < 0) {
        PUT_ERROR_ERRNO(pctx, STM32_R_CIPHER_INIT_FAILED,
                        "AF_ALG cipher accept");
        return -1;
    }
    return op_fd;
}

static int afalg_send_first(PROV_CTX *pctx, int op_fd,
                             int encrypt,
                             const unsigned char *iv, size_t ivlen,
                             const unsigned char *in, size_t inl,
                             int more)
{
    struct msghdr   msg;
    struct iovec    iov;
    struct cmsghdr *cmsg;
    struct af_alg_iv *alg_iv;

    char cbuf[CMSG_SPACE(sizeof(__u32)) +
              CMSG_SPACE(sizeof(struct af_alg_iv) + 16)];

    memset(&msg,  0, sizeof(msg));
    memset(cbuf,  0, sizeof(cbuf));

    iov.iov_base       = (void *)in;
    iov.iov_len        = inl;
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    cmsg             = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type  = ALG_SET_OP;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(__u32));
    *((__u32 *)CMSG_DATA(cmsg)) = encrypt ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;

    cmsg             = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type  = ALG_SET_IV;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(struct af_alg_iv) + ivlen);
    alg_iv           = (struct af_alg_iv *)CMSG_DATA(cmsg);
    alg_iv->ivlen    = (unsigned int)ivlen;
    if (iv != NULL && ivlen > 0)
        memcpy(alg_iv->iv, iv, ivlen);

    if (sendmsg(op_fd, &msg, more ? MSG_MORE : 0) < 0) {
        PUT_ERROR_ERRNO(pctx, STM32_R_CIPHER_UPDATE_FAILED,
                        "AF_ALG cipher sendmsg (first)");
        return 0;
    }
    return 1;
}

static int afalg_send_more(PROV_CTX *pctx, int op_fd,
                            const unsigned char *in, size_t inl,
                            int more)
{
    size_t  off = 0;
    ssize_t ret;

    while (off < inl) {
        ret = send(op_fd, in + off, inl - off, more ? MSG_MORE : 0);
        if (ret < 0) {
            PUT_ERROR_ERRNO(pctx, STM32_R_CIPHER_UPDATE_FAILED,
                            "AF_ALG cipher send");
            return 0;
        }
        off += (size_t)ret;
    }
    return 1;
}

static int afalg_recv(PROV_CTX *pctx, int op_fd,
                      unsigned char *out, size_t len)
{
    size_t  off = 0;
    ssize_t ret;

    while (off < len) {
        ret = read(op_fd, out + off, len - off);
        if (ret < 0) {
            PUT_ERROR_ERRNO(pctx, STM32_R_CIPHER_UPDATE_FAILED,
                            "AF_ALG cipher read");
            return 0;
        }
        if (ret == 0)
            break;
        off += (size_t)ret;
    }

    if (off != len) {
        PUT_ERROR(pctx, STM32_R_CIPHER_UPDATE_FAILED,
                  "AF_ALG cipher read: got %zu bytes, expected %zu", off, len);
        return 0;
    }
    return 1;
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
    PROV_CTX             *pctx = (PROV_CTX *)vprovctx;
    STM32_CIPHER_HW_CTX  *ctx;

    if (pctx == NULL || alg_name == NULL || keylen == 0) {
        PUT_ERROR(pctx, STM32_R_INVALID_ARGUMENT,
                  "invalid AF_ALG cipher newctx arguments");
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        PUT_ERROR(pctx, STM32_R_CIPHER_NEWCTX_FAILED,
                  "failed to allocate AF_ALG cipher context");
        return NULL;
    }

    ctx->provctx    = pctx;
    ctx->tf_fd      = -1;
    ctx->op_fd      = -1;
    ctx->mode       = mode;
    ctx->first_send = 1;

    ctx->ivlen = (mode == STM32_CIPHER_MODE_ECB) ? 0 : 16;

    ctx->tf_fd = afalg_open_tfm(pctx, alg_name);
    if (ctx->tf_fd < 0) {
        OPENSSL_free(ctx);
        return NULL;
    }
    return ctx;
}

void stm32_cipher_freectx(STM32_CIPHER_HW_CTX *ctx)
{
    if (ctx == NULL)
        return;
    afalg_close_fd(&ctx->op_fd);
    afalg_close_fd(&ctx->tf_fd);
    OPENSSL_free(ctx);
}

int stm32_cipher_init(STM32_CIPHER_HW_CTX *ctx,
                      const unsigned char *key, size_t keylen,
                      const unsigned char *iv,  size_t ivlen,
                      int encrypt)
{
    if (ctx == NULL || ctx->tf_fd < 0) {
        PUT_ERROR(ctx->provctx, STM32_R_CIPHER_INIT_FAILED,
                  "invalid AF_ALG cipher transform fd");
        return 0;
    }

    afalg_close_fd(&ctx->op_fd);
    ctx->first_send = 1;
    ctx->encrypt    = encrypt;

    if (!afalg_set_key(ctx->provctx, ctx->tf_fd, key, keylen))
        return 0;

    ctx->op_fd = afalg_open_op(ctx->provctx, ctx->tf_fd);
    if (ctx->op_fd < 0)
        return 0;

    if (iv != NULL && ivlen > 0)
        memcpy(ctx->iv, iv, ivlen < 16 ? ivlen : 16);
    else
        memset(ctx->iv, 0, sizeof(ctx->iv));

    return 1;
}

int stm32_cipher_update(STM32_CIPHER_HW_CTX *ctx,
                        unsigned char *out, size_t *outl,
                        const unsigned char *in, size_t inl)
{
    if (ctx == NULL || ctx->op_fd < 0) {
        PUT_ERROR(ctx->provctx, STM32_R_CIPHER_UPDATE_FAILED,
                  "AF_ALG cipher op_fd not open");
        return 0;
    }

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (ctx->first_send) {
        if (!afalg_send_first(ctx->provctx, ctx->op_fd,
                              ctx->encrypt,
                              ctx->iv, ctx->ivlen,
                              in, inl, 0))
            return 0;
        ctx->first_send = 0;
    } else {
        if (!afalg_send_more(ctx->provctx, ctx->op_fd, in, inl, 0))
            return 0;
    }

    if (!afalg_recv(ctx->provctx, ctx->op_fd, out, inl))
        return 0;

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