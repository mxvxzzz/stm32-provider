#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/engine.h>

// $CC evp_test.c -o evp_test -lcrypto -ldl -lpthread

#define IMPL_SOFT          "soft"
#define IMPL_STM32PROV     "stm32prov"
#define IMPL_PV_AFALG      "pv_afalg"
#define IMPL_PV_CRYPTODEV  "pv_cryptodev"
#define IMPL_ENG_AFALG     "eng_afalg"
#define IMPL_ENG_CRYPTODEV "eng_cryptodev"

#define PROPQUERY_STM32 "provider=stm32"

#define EVP_CHECK(x, msg) \
	do { if (!(x)) { fprintf(stderr, "Error: %s\n", (msg)); goto cleanup; } } while (0)

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

static size_t key_len_from_algo(const char *algo)
{
	if (strncmp(algo, "aes-128", 7) == 0) return 16;
	if (strncmp(algo, "aes-192", 7) == 0) return 24;
	if (strncmp(algo, "aes-256", 7) == 0) return 32;
	return 0;
}

static int is_engine(const char *impl)
{
	return strcmp(impl, IMPL_ENG_AFALG) == 0 ||
	       strcmp(impl, IMPL_ENG_CRYPTODEV) == 0;
}

static const char *engine_name_from_impl(const char *impl)
{
	if (strcmp(impl, IMPL_ENG_AFALG) == 0) return "afalg";
	if (strcmp(impl, IMPL_ENG_CRYPTODEV) == 0) return "devcrypto";
	return NULL;
}

static int hex_decode(const char *hex, unsigned char *out, size_t outmax, size_t *outlen)
{
	size_t hexlen = strlen(hex);
	size_t n;

	if (hexlen % 2 != 0)
		return -1;
	n = hexlen / 2;
	if (n > outmax)
		return -1;
	for (size_t i = 0; i < n; i++) {
		unsigned int byte;
		if (sscanf(hex + 2 * i, "%2x", &byte) != 1)
			return -1;
		out[i] = (unsigned char)byte;
	}
	*outlen = n;
	return 0;
}

static unsigned char *read_file(const char *path, long *outlen)
{
	FILE *f;
	long size;
	unsigned char *buf;

	f = fopen(path, "rb");
	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
	size = ftell(f);
	if (size < 0) { fclose(f); return NULL; }
	if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }

	buf = malloc(size > 0 ? (size_t)size : 1);
	if (!buf) { fclose(f); return NULL; }

	if (size > 0 && fread(buf, 1, (size_t)size, f) != (size_t)size) {
		free(buf);
		fclose(f);
		return NULL;
	}
	fclose(f);
	*outlen = size;
	return buf;
}

static int write_file(const char *path, const unsigned char *buf, long len)
{
	FILE *f = fopen(path, "wb");
	if (!f)
		return -1;
	if (len > 0 && fwrite(buf, 1, (size_t)len, f) != (size_t)len) {
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

int main(int argc, char *argv[])
{
	if (argc != 8) {
		fprintf(stderr,
			"Usage: %s <impl> <enc|dec> <algo> <key_hex> <iv_hex|-> <infile> <outfile>\n",
			argv[0]);
		return 1;
	}

	const char *impl    = argv[1];
	const char *op      = argv[2];
	const char *algo    = argv[3];
	const char *key_hex = argv[4];
	const char *iv_hex  = argv[5];
	const char *infile  = argv[6];
	const char *outfile = argv[7];

	int do_encrypt;
	if (strcmp(op, "enc") == 0) {
		do_encrypt = 1;
	} else if (strcmp(op, "dec") == 0) {
		do_encrypt = 0;
	} else {
		fprintf(stderr, "Error: op must be enc or dec\n");
		return 1;
	}

	const char *cipher_name = cipher_name_from_algo(algo);
	if (!cipher_name) {
		fprintf(stderr, "Error: unsupported algo: %s\n", algo);
		return 1;
	}

	size_t expected_keylen = key_len_from_algo(algo);
	int use_iv = needs_iv(algo);

	unsigned char key[32];
	unsigned char iv[16];
	size_t keylen = 0, ivlen = 0;

	if (hex_decode(key_hex, key, sizeof(key), &keylen) != 0 || keylen != expected_keylen) {
		fprintf(stderr, "Error: invalid key for %s (expected %zu bytes)\n", algo, expected_keylen);
		return 1;
	}

	if (use_iv) {
		if (strcmp(iv_hex, "-") == 0 ||
		    hex_decode(iv_hex, iv, sizeof(iv), &ivlen) != 0 || ivlen != 16) {
			fprintf(stderr, "Error: invalid iv for %s (expected 16 bytes)\n", algo);
			return 1;
		}
	}

	unsigned char *inbuf = NULL;
	unsigned char *outbuf = NULL;
	long inlen = 0;
	EVP_CIPHER_CTX *ctx = NULL;
	ENGINE *eng = NULL;
	OSSL_PROVIDER *prov_main = NULL;
	OSSL_PROVIDER *prov_default = NULL;
	EVP_CIPHER *cipher_fetch = NULL;
	const EVP_CIPHER *cipher = NULL;
	int ret = 1;

	if (strcmp(impl, IMPL_SOFT) == 0) {
		cipher = EVP_get_cipherbyname(cipher_name);
		EVP_CHECK(cipher, "EVP_get_cipherbyname failed");

	} else if (strcmp(impl, IMPL_PV_AFALG) == 0 || strcmp(impl, IMPL_PV_CRYPTODEV) == 0
			|| strcmp(impl, IMPL_STM32PROV) == 0) {
		prov_default = OSSL_PROVIDER_load(NULL, "default");
		prov_main = OSSL_PROVIDER_load(NULL, impl);
		EVP_CHECK(prov_main, "OSSL_PROVIDER_load failed");

		cipher_fetch = EVP_CIPHER_fetch(NULL, cipher_name, PROPQUERY_STM32);
		EVP_CHECK(cipher_fetch, "EVP_CIPHER_fetch failed");
		cipher = cipher_fetch;

	} else if (is_engine(impl)) {
		OpenSSL_add_all_algorithms();
		ENGINE_load_builtin_engines();

		const char *eng_name = engine_name_from_impl(impl);
		EVP_CHECK(eng_name, "unknown engine impl");

		eng = ENGINE_by_id(eng_name);
		EVP_CHECK(eng, "ENGINE_by_id failed");
		EVP_CHECK(ENGINE_init(eng), "ENGINE_init failed");

		cipher = EVP_get_cipherbyname(cipher_name);
		EVP_CHECK(cipher, "EVP_get_cipherbyname failed");

	} else {
		fprintf(stderr, "Error: unknown impl: %s\n", impl);
		goto cleanup;
	}

	inbuf = read_file(infile, &inlen);
	EVP_CHECK(inbuf, "failed to read infile");

	outbuf = malloc((size_t)inlen + EVP_MAX_BLOCK_LENGTH);
	EVP_CHECK(outbuf, "malloc failed");

	ctx = EVP_CIPHER_CTX_new();
	EVP_CHECK(ctx, "EVP_CIPHER_CTX_new failed");

	{
		int outlen = 0, tmplen = 0;

		if (do_encrypt) {
			EVP_CHECK(EVP_EncryptInit_ex(ctx, cipher, is_engine(impl) ? eng : NULL,
			                              key, use_iv ? iv : NULL),
			          "EncryptInit failed");
			EVP_CHECK(EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, (int)inlen),
			          "EncryptUpdate failed");
			EVP_CHECK(EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen),
			          "EncryptFinal failed");
		} else {
			EVP_CHECK(EVP_DecryptInit_ex(ctx, cipher, is_engine(impl) ? eng : NULL,
			                              key, use_iv ? iv : NULL),
			          "DecryptInit failed");
			EVP_CHECK(EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, (int)inlen),
			          "DecryptUpdate failed");
			EVP_CHECK(EVP_DecryptFinal_ex(ctx, outbuf + outlen, &tmplen),
			          "DecryptFinal failed");
		}

		EVP_CHECK(write_file(outfile, outbuf, outlen + tmplen) == 0,
		          "failed to write outfile");
	}

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