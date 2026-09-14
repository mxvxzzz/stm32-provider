#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

// $CC evp_test.c -o evp_test -lcrypto -ldl -lpthread

#define IMPL_SOFT      "soft"
#define IMPL_AFALG     "st_afalg"
#define IMPL_CRYPTODEV "st_cryptodev"
#define IMPL_STM32PROV "stm32prov"

#define PROVIDER_NAME_DEFAULT "default"
#define PROPQUERY_STM32       "provider=stm32"

#define EVP_CHECK(x, msg) \
	do { if (!(x)) { fprintf(stderr, "Error: %s\n", (msg)); goto cleanup; } } while (0)

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

int main(int argc, char *argv[])
{
	if (argc != 4) {
		fprintf(stderr, "Usage: %s <impl> <algo> <infile>\n", argv[0]);
		return 1;
	}

	const char *impl   = argv[1];
	const char *algo   = argv[2];
	const char *infile = argv[3];

	OSSL_PROVIDER *prov_main    = NULL;
	OSSL_PROVIDER *prov_default = NULL;
	EVP_MD_CTX    *ctx          = NULL;
	EVP_MD        *md           = NULL;
	unsigned char *inbuf        = NULL;
	long           inlen        = 0;
	int            ret          = 1;

	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int  digest_len = 0;

	if (strcmp(impl, IMPL_SOFT) == 0) {
		md = EVP_MD_fetch(NULL, algo, NULL);
		EVP_CHECK(md, "EVP_MD_fetch failed");

	} else if (strcmp(impl, IMPL_AFALG) == 0 || strcmp(impl, IMPL_CRYPTODEV) == 0 || strcmp(impl, IMPL_STM32PROV) == 0) {
		prov_default = OSSL_PROVIDER_load(NULL, PROVIDER_NAME_DEFAULT);
		EVP_CHECK(prov_default, "OSSL_PROVIDER_load default failed");
		prov_main = OSSL_PROVIDER_load(NULL, impl);
		EVP_CHECK(prov_main, "OSSL_PROVIDER_load failed");

		md = EVP_MD_fetch(NULL, algo, PROPQUERY_STM32);
		EVP_CHECK(md, "EVP_MD_fetch failed");

	} else {
		fprintf(stderr, "Error: unknown impl: %s\n", impl);
		goto cleanup;
	}

	inbuf = read_file(infile, &inlen);
	EVP_CHECK(inbuf, "failed to read infile");

	ctx = EVP_MD_CTX_new();
	EVP_CHECK(ctx, "EVP_MD_CTX_new failed");

	EVP_CHECK(EVP_DigestInit_ex(ctx, md, NULL), "EVP_DigestInit_ex failed");
	EVP_CHECK(EVP_DigestUpdate(ctx, inbuf, (size_t)inlen), "EVP_DigestUpdate failed");
	EVP_CHECK(EVP_DigestFinal_ex(ctx, digest, &digest_len), "EVP_DigestFinal_ex failed");

	for (unsigned int i = 0; i < digest_len; i++)
		printf("%02x", digest[i]);
	printf("\n");

	ret = 0;

cleanup:
	if (ctx)          EVP_MD_CTX_free(ctx);
	if (md)           EVP_MD_free(md);
	if (prov_main)    OSSL_PROVIDER_unload(prov_main);
	if (prov_default) OSSL_PROVIDER_unload(prov_default);
	free(inbuf);
	return ret;
}