#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

#include <openssl/core.h>
#include <openssl/crypto.h>

#include "cipher.h"
#include "../include/prov.h"
#include "../include/err.h"

/* Size maximal of one crypto request
 * without MSG_MORE
 */
#define MAX_REQ_SIZE (196U * 1024U)


static void afalg_close_fd(int *fd);
static int  afalg_open_tfm(PROV_CTX *pctx, const char *alg_name);
static int  afalg_set_key(PROV_CTX *pctx, int tf_fd,
                          const unsigned char *key, size_t keylen);
static int  afalg_open_op(PROV_CTX *pctx, int tf_fd);
static int afalg_send_request(PROV_CTX *pctx, int op_fd, int encrypt,
                              const unsigned char *iv, size_t ivlen,
                              const unsigned char *in, size_t inl);
static int  afalg_recv(PROV_CTX *pctx, int op_fd,
                       unsigned char *out, size_t len);
static void afalg_ctr_increment(unsigned char *counter,
				size_t counter_len, size_t blocks);


/*********************************************************************
 *
 *  Contexte AF_ALG
 *
 *****/
struct __stm32_cipher_hw_ctx_st__ {
    PROV_CTX          *provctx;
    int                tf_fd;
    STM32_CIPHER_MODE  mode;
    size_t             ivlen;
    int                encrypt;
    unsigned char      iv[STM32_AES_BLOCK_SIZE];
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
    OPENSSL_strlcpy((char *)sa.salg_name, alg_name, sizeof(sa.salg_name));

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

/*
 * Send one req crypto complete 
 */
static int afalg_send_request(PROV_CTX *pctx, int op_fd, int encrypt,
                              const unsigned char *iv, size_t ivlen,
                              const unsigned char *in, size_t inl)
{
    struct msghdr msg;
    struct iovec iov;
    struct cmsghdr *cmsg;
    struct af_alg_iv *alg_iv;
    ssize_t sent;
    int has_iv;

    /*
     * L'union garantit un alignement correct du buffer
     * pour struct cmsghdr.
     */
    union {
        struct cmsghdr align;
        unsigned char buffer[
            CMSG_SPACE(sizeof(__u32)) +
            CMSG_SPACE(sizeof(struct af_alg_iv) + STM32_AES_BLOCK_SIZE)
        ];
    } control;

    if (op_fd < 0 || in == NULL || inl == 0) {
        PUT_ERROR(pctx, STM32_R_INVALID_ARGUMENT, "invalid AF_ALG cipher request");
        return 0;
    }

    if (inl > MAX_REQ_SIZE) {
        PUT_ERROR(pctx, STM32_R_CIPHER_UPDATE_FAILED, "AF_ALG cipher request too large: "
                  "got %zu bytes, maximum is %u", inl,(unsigned int)MAX_REQ_SIZE);
        return 0;
    }

    if (ivlen > STM32_AES_BLOCK_SIZE) {
        PUT_ERROR(pctx, STM32_R_INVALID_ARGUMENT, "AF_ALG cipher IV too large: "
                  "got %zu bytes, maximum is %u", ivlen, STM32_AES_BLOCK_SIZE);
        return 0;
    }

    has_iv = (iv != NULL && ivlen > 0);

    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));
    memset(&control, 0, sizeof(control));

    iov.iov_base = (void *)in;
    iov.iov_len = inl;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.buffer;

    if (has_iv) {
        msg.msg_controllen =
            CMSG_SPACE(sizeof(__u32)) +
            CMSG_SPACE(sizeof(struct af_alg_iv) + ivlen);
    } else {
        msg.msg_controllen =
            CMSG_SPACE(sizeof(__u32));
    }

    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL) {
        PUT_ERROR(pctx, STM32_R_CIPHER_UPDATE_FAILED,
                  "AF_ALG cipher missing ALG_SET_OP");
        return 0;
    }

    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(__u32));

    *((__u32 *)CMSG_DATA(cmsg)) = encrypt ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;

    if (has_iv) {
        cmsg = CMSG_NXTHDR(&msg, cmsg);
        if (cmsg == NULL) {
            PUT_ERROR(pctx, STM32_R_CIPHER_UPDATE_FAILED, "AF_ALG cipher missing ALG_SET_IV");
            return 0;
        }

        cmsg->cmsg_level = SOL_ALG;
        cmsg->cmsg_type = ALG_SET_IV;
        cmsg->cmsg_len =
            CMSG_LEN(sizeof(struct af_alg_iv) + ivlen);

        alg_iv = (struct af_alg_iv *)CMSG_DATA(cmsg);
        alg_iv->ivlen = (unsigned int)ivlen;

        memcpy(alg_iv->iv, iv, ivlen);
    }

    sent = sendmsg(op_fd, &msg, 0);
    if (sent < 0) {
        PUT_ERROR_ERRNO(pctx, STM32_R_CIPHER_UPDATE_FAILED, "AF_ALG cipher sendmsg");
        return 0;
    }

    if ((size_t)sent != inl) {
        PUT_ERROR(pctx, STM32_R_CIPHER_UPDATE_FAILED, "AF_ALG cipher partial send: "
                  "got %zd bytes, expected %zu", sent, inl);
        return 0;
    }

    return 1;
}

static int afalg_recv(PROV_CTX *pctx, int op_fd,
                      unsigned char *out, size_t len)
{
    size_t  off = 0;
    ssize_t ret;

   if (op_fd < 0 || out == NULL || len == 0) {
        PUT_ERROR(pctx, STM32_R_INVALID_ARGUMENT,
                  "invalid AF_ALG cipher receive request");
        return 0;
    }

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

/*

 */
static void afalg_ctr_increment(unsigned char *counter, size_t counter_len, size_t blocks)
{
    size_t i;

    if (counter == NULL || counter_len == 0)
        return;

    i = counter_len;

    while (i > 0 && blocks > 0) {
        unsigned int sum;

        i--;

        sum = (unsigned int)counter[i] + (unsigned int)(blocks & 0xffU);

        counter[i] = (unsigned char)(sum & 0xffU);
        blocks = (blocks >> 8) + (size_t)(sum >> 8);
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
    PROV_CTX *pctx = (PROV_CTX *)vprovctx;
    STM32_CIPHER_HW_CTX *ctx;

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
    ctx->mode       = mode;

    ctx->ivlen = (mode == STM32_CIPHER_MODE_ECB) ? 0 : STM32_AES_BLOCK_SIZE;

    memset(ctx->iv, 0, sizeof(ctx->iv));

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

    afalg_close_fd(&ctx->tf_fd);
    OPENSSL_free(ctx);
}

int stm32_cipher_init(STM32_CIPHER_HW_CTX *ctx,
                      const unsigned char *key, size_t keylen,
                      const unsigned char *iv,  size_t ivlen,
                      int encrypt)
{
    if (ctx == NULL)
        return 0;

    if (ctx->tf_fd < 0) {
        PUT_ERROR(ctx->provctx, STM32_R_CIPHER_INIT_FAILED,
                  "invalid AF_ALG cipher transform fd");
        return 0;
    }

    if (ctx->ivlen > 0) {
        if (iv == NULL || ivlen != ctx->ivlen) {
            PUT_ERROR(ctx->provctx, STM32_R_INVALID_ARGUMENT,
                      "invalid AF_ALG cipher IV length: got %zu bytes, expected %zu",
                      ivlen, ctx->ivlen);
            return 0;
        }
    } else {
        /*
         * No IV for ECB mode.
         */
        if (ivlen != 0) {
            PUT_ERROR(ctx->provctx, STM32_R_INVALID_ARGUMENT,
                      "AF_ALG ECB cipher does not use an IV");
            return 0;
        }
    }
    
    if (!afalg_set_key(ctx->provctx, ctx->tf_fd, key, keylen))
        return 0;

    ctx->encrypt = encrypt;

    if (ctx->ivlen > 0)
        memcpy(ctx->iv, iv, ctx->ivlen);
    else
        memset(ctx->iv, 0, sizeof(ctx->iv));

    return 1;
}

int stm32_cipher_update(STM32_CIPHER_HW_CTX *ctx,
                        unsigned char *out, size_t *outl,
                        const unsigned char *in, size_t inl)
{
    size_t off;

    if (outl == NULL)
	return 0;

    *outl = 0;

    if (inl == 0)
        return 1;

    if (ctx == NULL)
        return 0;

    if (ctx->tf_fd < 0) {
        PUT_ERROR(ctx->provctx, STM32_R_CIPHER_UPDATE_FAILED,
                  "AF_ALG cipher transform fd not open");
        return 0;
    }

    if (inl == 0)
        return 1;

    if (in == NULL || out == NULL) {
        PUT_ERROR(ctx->provctx,
                  STM32_R_INVALID_ARGUMENT,
                  "invalid AF_ALG cipher update buffers");
        return 0;
    }

    if ((ctx->mode == STM32_CIPHER_MODE_CBC ||
         ctx->mode == STM32_CIPHER_MODE_ECB) && (inl % STM32_AES_BLOCK_SIZE) != 0) {
        PUT_ERROR(ctx->provctx, STM32_R_CIPHER_UPDATE_FAILED,
                  "AF_ALG cipher input is not block aligned: %zu bytes", inl);
        return 0;
    }

    off = 0;

    while (off < inl) {
        size_t req_len;
        int op_fd;

        unsigned char next_iv[STM32_AES_BLOCK_SIZE];

        req_len = inl - off;

        if (req_len > MAX_REQ_SIZE)
            req_len = MAX_REQ_SIZE;


        if (ctx->mode == STM32_CIPHER_MODE_CBC ||
            ctx->mode == STM32_CIPHER_MODE_ECB) {
            req_len -= req_len % STM32_AES_BLOCK_SIZE;
        }

        if (req_len == 0) {
            PUT_ERROR(ctx->provctx, STM32_R_CIPHER_UPDATE_FAILED,
                      "AF_ALG cipher zero-length request after block alignment");
            return 0;
        }

        memset(next_iv, 0, sizeof(next_iv));

        if (ctx->mode == STM32_CIPHER_MODE_CBC &&
            !ctx->encrypt) {
            memcpy(next_iv,
                   in + off + req_len - STM32_AES_BLOCK_SIZE,
                   STM32_AES_BLOCK_SIZE);
        }

        /*
         * Each bloc correspond of a new crypto request
         */
        op_fd = afalg_open_op(ctx->provctx,
                              ctx->tf_fd);
        if (op_fd < 0)
            return 0;

        if (!afalg_send_request(ctx->provctx, op_fd, ctx->encrypt,
                		ctx->ivlen > 0 ? ctx->iv : NULL, ctx->ivlen,
                		in + off, req_len)) {
            afalg_close_fd(&op_fd);
            OPENSSL_cleanse(next_iv, sizeof(next_iv));
            return 0;
        }

        if (!afalg_recv(ctx->provctx, op_fd, out + off, req_len)) {
            afalg_close_fd(&op_fd);
            OPENSSL_cleanse(next_iv, sizeof(next_iv));
            return 0;
        }

        afalg_close_fd(&op_fd);

        if (ctx->mode == STM32_CIPHER_MODE_CBC) {
            if (ctx->encrypt)
                memcpy(ctx->iv, out + off + req_len - STM32_AES_BLOCK_SIZE, STM32_AES_BLOCK_SIZE);
            else 
                memcpy(ctx->iv, next_iv, STM32_AES_BLOCK_SIZE);
        } else if (ctx->mode == STM32_CIPHER_MODE_CTR) {
		size_t blocks;

		blocks = (req_len + STM32_AES_BLOCK_SIZE - 1) / STM32_AES_BLOCK_SIZE;

		afalg_ctr_increment(ctx->iv,ctx->ivlen, blocks);
	}

        OPENSSL_cleanse(next_iv, sizeof(next_iv));

        off += req_len;
    }

    *outl = off;
    return 1;
}

int stm32_cipher_final(STM32_CIPHER_HW_CTX *ctx,
                       unsigned char *out, size_t *outl)
{
    (void)ctx;
    (void)out;

    if (outl == NULL)
	return 0;

    *outl = 0;
    return 1;
}