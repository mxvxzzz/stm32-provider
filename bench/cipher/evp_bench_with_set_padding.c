#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sched.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/engine.h>

// $CC evp_bench_with_set_padding.c -o evp_padding -lcrypto -ldl -lpthread

#define BENCH_CORE 0

#define IMPL_SOFT          "soft"
#define IMPL_PV_AFALG      "pv_afalg"
#define IMPL_PV_CRYPTODEV  "pv_cryptodev"
#define IMPL_ENG_AFALG     "eng_afalg"
#define IMPL_ENG_CRYPTODEV "eng_cryptodev"

#define PROPQUERY_STM32 "provider=stm32"

#define EVP_CHECK(x, msg) \
	do { if (!(x)) { fprintf(stderr, "Error: %s\n", (msg)); goto cleanup; } } while (0)

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

static const char *cipher_name_from_algo(const char *algo)
{
	if (strcmp(algo, "aes-128-cbc") == 0) return "AES-128-CBC";
	if (strcmp(algo, "aes-192-cbc") == 0) return "AES-192-CBC";
	if (strcmp(algo, "aes-256-cbc") == 0) return "AES-256-CBC";
	if (strcmp(algo, "aes-128-ctr") == 0) return "AES-128-CTR";
	if (strcmp(algo, "aes-192-ctr") == 0) return "AES-192-CTR";
	if (strcmp(algo, "aes-256-ctr") == 0) return "AES-256-CTR";
	if (strcmp(algo, "aes-128-ecb") == 0) return "AES-128-ECB";
	if (strcmp(algo, "aes-192-ecb") == 0) return "AES-192-ECB";
	if (strcmp(algo, "aes-256-ecb") == 0) return "AES-256-ECB";
	return NULL;
}

static int needs_iv(const char *algo)
{
	return strstr(algo, "-ecb") == NULL;
}

static const char *engine_name_from_impl(const char *impl)
{
	if (strcmp(impl, IMPL_ENG_AFALG) == 0) return "afalg";
	if (strcmp(impl, IMPL_ENG_CRYPTODEV) == 0) return "devcrypto";
	return NULL;
}

int main(int argc, char *argv[])
{
	if (argc != 5) {
		fprintf(stderr, "Usage: %s <impl> <seconds> <block_size> <algo>\n", argv[0]);
		return 1;
	}

	const char *impl = argv[1];
	int seconds = atoi(argv[2]);
	size_t block_size = (size_t)atol(argv[3]);
	const char *algo = argv[4];

	if (seconds <= 0 || block_size == 0) {
		fprintf(stderr, "Error: invalid seconds or block_size\n");
		return 1;
	}

	if (pin_to_core(BENCH_CORE) != 0)
		fprintf(stderr, "Warning: sched_setaffinity failed\n");

	int use_iv = needs_iv(algo);

	unsigned char key[32];
	unsigned char iv[16];
	memset(key, 0x11, sizeof(key));
	memset(iv, 0x22, sizeof(iv));

	unsigned char *inbuf = NULL;
	unsigned char *outbuf = NULL;
	EVP_CIPHER_CTX *ctx = NULL;
	ENGINE *eng = NULL;
	OSSL_PROVIDER *prov_main = NULL;
	OSSL_PROVIDER *prov_default = NULL;
	EVP_CIPHER *cipher_fetch = NULL;
	const EVP_CIPHER *cipher = NULL;
	int ret = 1;

	const char *cipher_name = cipher_name_from_algo(algo);
	if (!cipher_name) {
		fprintf(stderr, "Error: unsupported algo: %s\n", algo);
		return 1;
	}

	if (strcmp(impl, IMPL_SOFT) == 0) {
		cipher = EVP_get_cipherbyname(cipher_name);
		if (!cipher) {
			fprintf(stderr, "Failed to get cipher: %s\n", cipher_name);
			goto cleanup;
		}

	} else if (strcmp(impl, IMPL_PV_AFALG) == 0) {
		prov_default = OSSL_PROVIDER_load(NULL, "default");
		prov_main = OSSL_PROVIDER_load(NULL, "pv_afalg");

		cipher_fetch = EVP_CIPHER_fetch(NULL, cipher_name, PROPQUERY_STM32);
		if (!cipher_fetch) {
			fprintf(stderr, "Failed to fetch cipher: %s\n", cipher_name);
			goto cleanup;
		}
		cipher = cipher_fetch;

	} else if (strcmp(impl, IMPL_PV_CRYPTODEV) == 0) {
		prov_default = OSSL_PROVIDER_load(NULL, "default");
		prov_main = OSSL_PROVIDER_load(NULL, "pv_cryptodev");

		cipher_fetch = EVP_CIPHER_fetch(NULL, cipher_name, PROPQUERY_STM32);
		if (!cipher_fetch) {
			fprintf(stderr, "Failed to fetch cipher: %s\n", cipher_name);
			goto cleanup;
		}
		cipher = cipher_fetch;

	} else if (strcmp(impl, IMPL_ENG_AFALG) == 0 || strcmp(impl, IMPL_ENG_CRYPTODEV) == 0) {

		OpenSSL_add_all_algorithms();
		ENGINE_load_builtin_engines();

		const char *eng_name = engine_name_from_impl(impl);
		if (!eng_name) {
			fprintf(stderr, "Unknown impl: %s\n", impl);
			goto cleanup;
		}

		eng = ENGINE_by_id(eng_name);
		if (!eng) {
			fprintf(stderr, "Failed to load engine: %s\n", eng_name);
			goto cleanup;
		}
		if (!ENGINE_init(eng)) {
			fprintf(stderr, "ENGINE_init failed\n");
			goto cleanup;
		}

		cipher = EVP_get_cipherbyname(cipher_name);
		if (!cipher) {
			fprintf(stderr, "Failed to get cipher: %s\n", cipher_name);
			goto cleanup;
		}

	} else {
		fprintf(stderr, "Unknown impl: %s\n", impl);
		goto cleanup;
	}

	inbuf = malloc(block_size);
	outbuf = malloc(block_size + 32);
	EVP_CHECK(inbuf && outbuf, "malloc failed");
	memset(inbuf, 0xAB, block_size);

	ctx = EVP_CIPHER_CTX_new();
	EVP_CHECK(ctx, "EVP_CIPHER_CTX_new failed");

	ENGINE *init_eng = (strcmp(impl, IMPL_ENG_AFALG) == 0 || strcmp(impl, IMPL_ENG_CRYPTODEV) == 0) ? eng : NULL;

	if (!EVP_EncryptInit_ex(ctx, cipher, init_eng, key, use_iv ? iv : NULL)) {
		fprintf(stderr, "EVP_EncryptInit_ex failed\n");
		goto cleanup;
	}

	if (!use_iv) {
		/* 0 : if data not aligned you must handle padding yourself,
		   1 : keep provider handle it.
		 */
		if (!EVP_CIPHER_CTX_set_padding(ctx, 0)) {
			fprintf(stderr, "EVP_CIPHER_CTX_set_padding failed\n");
			goto cleanup;
		}
	}

	long ops = 0;
	double t_start = now_sec();
	double deadline = t_start + seconds;

	while (1) {
		if (now_sec() >= deadline)
			break;

		int outlen = 0;

		EVP_CHECK(EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, (int)block_size),
			"EVP_EncryptUpdate failed");

		ops++;
	}

	double elapsed = now_sec() - t_start;

	int outlen = 0;
	EVP_CHECK(EVP_EncryptFinal_ex(ctx, outbuf, &outlen),
		"EVP_EncryptFinal_ex failed");

	double total_bytes = (double)ops * (double)block_size;
	double kbps = (total_bytes / elapsed) / 1024.0;

	printf("%s        %.2fk\n", algo, kbps);

	ret = 0;

cleanup:
	if (ctx) EVP_CIPHER_CTX_free(ctx);
	if (eng) {
		ENGINE_finish(eng);
		ENGINE_free(eng);
	}
	if (cipher_fetch) EVP_CIPHER_free(cipher_fetch);
	if (prov_main) OSSL_PROVIDER_unload(prov_main);
	if (prov_default) OSSL_PROVIDER_unload(prov_default);
	free(inbuf);
	free(outbuf);
	return ret;
}