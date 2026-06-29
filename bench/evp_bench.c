#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sched.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#define IMPL_AFALG      "st_afalg"
#define IMPL_CRYPTODEV  "st_cryptodev"
#define IMPL_IS(s)      (strcmp(impl, (s)) == 0)

#define PROVIDER_NAME_AFALG     "st_afalg"
#define PROVIDER_NAME_CRYPTODEV "st_cryptodev"
#define PROVIDER_NAME_DEFAULT   "default"
#define PROPQUERY_STM32         "provider=stm32"

#define BENCH_CORE 0

#define EVP_CHECK(x, msg) \
    do { if (!(x)) { fprintf(stderr, "Error: %s\n", (msg)); goto cleanup; } } while(0)

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static int pin_to_core(int core)
{
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(core, &mask);
    return sched_setaffinity(0, sizeof(mask), &mask);
}

int main(int argc, char *argv[])
{
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <impl> <seconds> <block_size> <algo>\n", argv[0]);
        return 1;
    }

    const char *impl       = argv[1];
    int         seconds    = atoi(argv[2]);
    size_t      block_size = (size_t)atol(argv[3]);
    const char *algo       = argv[4];

    if (pin_to_core(BENCH_CORE) != 0)
        fprintf(stderr, "Warning: sched_setaffinity failed\n");

    OSSL_PROVIDER *prov_main    = NULL;
    OSSL_PROVIDER *prov_default = NULL;
    EVP_MD_CTX    *ctx          = NULL;
    EVP_MD        *md           = NULL;
    unsigned char *buf          = NULL;
    int            ret          = 1;

#define LOAD_PROVIDER(var, name) \
    do { \
        (var) = OSSL_PROVIDER_load(NULL, (name)); \
        if (!(var)) { fprintf(stderr, "Failed to load provider: %s\n", (name)); goto cleanup; } \
    } while(0)

    if (IMPL_IS(IMPL_AFALG)) {
        LOAD_PROVIDER(prov_main,    PROVIDER_NAME_AFALG);
        LOAD_PROVIDER(prov_default, PROVIDER_NAME_DEFAULT);
    } else if (IMPL_IS(IMPL_CRYPTODEV)) {
        LOAD_PROVIDER(prov_main,    PROVIDER_NAME_CRYPTODEV);
        LOAD_PROVIDER(prov_default, PROVIDER_NAME_DEFAULT);
    } else {
        fprintf(stderr, "Unknown impl: %s\n", impl);
        goto cleanup;
    }

    buf = malloc(block_size);
    EVP_CHECK(buf, "malloc failed");
    memset(buf, 0xAB, block_size);

    unsigned char digest[64];
    unsigned int  digest_len = 0;

    ctx = EVP_MD_CTX_new();
    EVP_CHECK(ctx, "EVP_MD_CTX_new failed");

    md = EVP_MD_fetch(NULL, algo, PROPQUERY_STM32);
    EVP_CHECK(md, "EVP_MD_fetch failed");
    EVP_CHECK(EVP_DigestInit_ex(ctx, md, NULL), "EVP_DigestInit_ex failed");

    long   ops      = 0;
    long   check    = 0;
    double t_start  = now_sec();
    double deadline = t_start + seconds;

    while (1) {
        EVP_CHECK(EVP_DigestUpdate(ctx, buf, block_size), "EVP_DigestUpdate failed");
        ops++;
        check++;
        if (check >= 1000) {
            check = 0;
            if (now_sec() >= deadline) break;
        }
    }

    double elapsed = now_sec() - t_start;

    EVP_CHECK(EVP_DigestFinal_ex(ctx, digest, &digest_len), "EVP_DigestFinal_ex failed");

    double total_bytes = (double)ops * (double)block_size;
    double kbps        = (total_bytes / elapsed) / 1024.0;

    printf("%s        %.2fk\n", algo, kbps);

    ret = 0;

cleanup:
    if (ctx)          EVP_MD_CTX_free(ctx);
    if (md)           EVP_MD_free(md);
    if (buf)          free(buf);
    if (prov_main)    OSSL_PROVIDER_unload(prov_main);
    if (prov_default) OSSL_PROVIDER_unload(prov_default);

    return ret;
}