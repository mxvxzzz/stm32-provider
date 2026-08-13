/*
 * stmaead - AES-GCM/CCM encrypt/decrypt via STM32 provider
 *
 * For files > 60KB, cut into chunks
 * with a unique nonce per chunk.
 *
 * Encrypted file format:
 *   [magic 4B "SGC1"][algo 1B][chunk_size 4B][nonce_len 1B][nonce][taglen 1B][aadlen 4B][aad]
 *   [chunk0_len 4B][chunk0_ct][chunk0_tag]
 *   [chunk1_len 4B][chunk1_ct][chunk1_tag]
 *   ...
 *   [0x00000000] <-- end
 *
 * $CC -o stmaead stmaead.c -lcrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>

#define CHUNK_SIZE     (60 * 1024)
#define MAGIC          "SGC1"
#define MAGIC_LEN      4
#define ALGO_GCM       1
#define ALGO_CCM       2

static int hex2bin(const char *hex, unsigned char *bin, size_t *outlen, size_t maxlen)
{
	size_t hexlen = strlen(hex), i;
	unsigned int byte;

	if (hexlen % 2 != 0 || hexlen / 2 > maxlen) 
		return 0;

	for (i = 0; i < hexlen / 2; i++) {
		if (sscanf(hex + 2*i, "%02x", &byte) != 1) 
			return 0;
		bin[i] = (unsigned char)byte;
	}
	*outlen = hexlen / 2;

	return 1;
}

static void nonce_increment(unsigned char *nonce, size_t nonce_len)
{
	int i;
	unsigned int carry = 1;

	for (i = (int)nonce_len - 1; i >= 0 && carry; i--) {
		carry += nonce[i];
		nonce[i] = (unsigned char)(carry & 0xFF);
		carry >>= 8;
	}
}

static void write_u32(FILE *f, uint32_t v)
{
	unsigned char b[4] = { v & 0xFF, (v>>8) & 0xFF, (v>>16) & 0xFF, (v>>24) & 0xFF };
	fwrite(b, 1, 4, f);
}

static uint32_t read_u32(FILE *f)
{
	unsigned char b[4] = {0};
	if (fread(b, 1, 4, f) != 4) 
		return 0;

	return b[0] | (b[1]<<8) | (b[2]<<16) | (b[3]<<24);
}

/*  GCM encrypt/decrypt one chunk  */
static int gcm_enc_chunk(EVP_CIPHER *cipher, const unsigned char *key, const unsigned char *nonce,
                         const unsigned char *aad, size_t aadlen, const unsigned char *in, size_t inl,
                         unsigned char *out, int *outl, unsigned char *tag, int taglen)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int tmpl = 0;

	if (!ctx) 
		return 0;

	if (!EVP_EncryptInit_ex(ctx, cipher, NULL, key, nonce)) 
		goto err;

	if (aadlen > 0 && !EVP_EncryptUpdate(ctx, NULL, outl, aad, (int)aadlen)) 
		goto err;

	if (inl > 0) { 
		if (!EVP_EncryptUpdate(ctx, out, outl, in, (int)inl)) 
			goto err;
	}
	else 
		*outl = 0;

	if (!EVP_EncryptFinal_ex(ctx, out + *outl, &tmpl)) 
		goto err;

	*outl += tmpl;

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, taglen, tag)) 
		goto err;

	EVP_CIPHER_CTX_free(ctx); 
		return 1;

err: 
	ERR_print_errors_fp(stderr); EVP_CIPHER_CTX_free(ctx); 
	return 0;
}

static int gcm_dec_chunk(EVP_CIPHER *cipher, const unsigned char *key, const unsigned char *nonce,
                         const unsigned char *aad, size_t aadlen, const unsigned char *in, size_t inl,
                         unsigned char *out, int *outl, unsigned char *tag, int taglen)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int tmpl = 0;

	if (!ctx) 
		return 0;

	if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key, nonce)) 
		goto err;

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, taglen, tag)) 
		goto err;

	if (aadlen > 0 && !EVP_DecryptUpdate(ctx, NULL, outl, aad, (int)aadlen)) 
		goto err;

	if (inl > 0) { 
		if (!EVP_DecryptUpdate(ctx, out, outl, in, (int)inl)) 
			goto err; 
	}
	else 
		*outl = 0;

	if (EVP_DecryptFinal_ex(ctx, out + *outl, &tmpl) <= 0)
		goto err;

	*outl += tmpl;

	EVP_CIPHER_CTX_free(ctx); 
		return 1;

err: 
	EVP_CIPHER_CTX_free(ctx); 
	return 0;
}

/*  CCM encrypt/decrypt one chunk  */
static int ccm_enc_chunk(EVP_CIPHER *cipher, const unsigned char *key,
                         const unsigned char *nonce, size_t nonce_len,
                         const unsigned char *aad, size_t aadlen,
                         const unsigned char *in, size_t inl,
                         unsigned char *out, int *outl,
                         unsigned char *tag, int taglen)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int tmpl = 0;

	if (!ctx)
		return 0;

	if (!EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL))
		goto err;

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce_len, NULL))
		goto err;

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, taglen, NULL))
		goto err;

	if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce))
		goto err;

	if (!EVP_EncryptUpdate(ctx, NULL, outl, NULL, (int)inl))
		goto err;

	if (aadlen > 0 && !EVP_EncryptUpdate(ctx, NULL, outl, aad, (int)aadlen))
		goto err;

	if (inl > 0) {
		if (!EVP_EncryptUpdate(ctx, out, outl, in, (int)inl))
			goto err;
	}
	else
		*outl = 0;

	if (!EVP_EncryptFinal_ex(ctx, out + *outl, &tmpl))
		goto err;

	*outl += tmpl;

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, taglen, tag))
		goto err;

	EVP_CIPHER_CTX_free(ctx);
	return 1;

err:
	ERR_print_errors_fp(stderr);
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

static int ccm_dec_chunk(EVP_CIPHER *cipher, const unsigned char *key,
                         const unsigned char *nonce, size_t nonce_len,
                         const unsigned char *aad, size_t aadlen,
                         const unsigned char *in, size_t inl,
                         unsigned char *out, int *outl,
                         unsigned char *tag, int taglen)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int tmpl = 0;

	if (!ctx)
		return 0;

	if (!EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL))
		goto err;

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce_len, NULL))
		goto err;

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, taglen, tag))
		goto err;

	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce))
		goto err;

	if (!EVP_DecryptUpdate(ctx, NULL, outl, NULL, (int)inl))
		goto err;

	if (aadlen > 0 && !EVP_DecryptUpdate(ctx, NULL, outl, aad, (int)aadlen))
		goto err;

	if (inl > 0) {
		if (!EVP_DecryptUpdate(ctx, out, outl, in, (int)inl))
			goto err;
	}
	else
		*outl = 0;

	if (EVP_DecryptFinal_ex(ctx, out + *outl, &tmpl) <= 0)
		goto err;

	*outl += tmpl;

	EVP_CIPHER_CTX_free(ctx);
	return 1;

err:
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

/*  Encrypt file  */
static int do_encrypt(EVP_CIPHER *cipher, int algo_id, const unsigned char *key,
                      const unsigned char *base_nonce, size_t nonce_len,
                      const unsigned char *aad, size_t aadlen, int taglen,
                      const char *in_path, const char *out_path)
{
	FILE *fin, *fout;
	unsigned char *inbuf, *outbuf, nonce[13], tag[16];
	size_t total_in = 0;
	int chunks = 0, outl, ret = 0;

	fin = fopen(in_path, "rb");
	if (!fin) {
		perror(in_path);
		return 0;
	}

	fout = fopen(out_path, "wb");
	if (!fout) {
		perror(out_path);
		fclose(fin);
		return 0;
	}

	inbuf = malloc(CHUNK_SIZE);
	outbuf = malloc(CHUNK_SIZE + 16);
	if (!inbuf || !outbuf)
		goto cleanup;

	memcpy(nonce, base_nonce, nonce_len);

	/* header */
	fwrite(MAGIC, 1, MAGIC_LEN, fout);
	fputc((unsigned char)algo_id, fout);
	write_u32(fout, CHUNK_SIZE);
	fputc((unsigned char)nonce_len, fout);
	fwrite(base_nonce, 1, nonce_len, fout);
	fputc((unsigned char)taglen, fout);
	write_u32(fout, (uint32_t)aadlen);
	if (aadlen > 0)
		fwrite(aad, 1, aadlen, fout);

	while (1) {
		size_t nr = fread(inbuf, 1, CHUNK_SIZE, fin);
		int ok;

		if (nr == 0)
			break;

		total_in += nr;
		outl = 0;

		if (algo_id == ALGO_GCM)
			ok = gcm_enc_chunk(cipher, key, nonce, (chunks == 0) ? aad : NULL,
			                   (chunks == 0) ? aadlen : 0, inbuf, nr, outbuf,
			                   &outl, tag, taglen);
		else
			ok = ccm_enc_chunk(cipher, key, nonce, nonce_len, (chunks == 0) ? aad : NULL,
			                   (chunks == 0) ? aadlen : 0, inbuf, nr, outbuf,
			                   &outl, tag, taglen);

		if (!ok) {
			fprintf(stderr, "Encrypt chunk %d failed\n", chunks);
			goto cleanup;
		}

		write_u32(fout, (uint32_t)nr);
		fwrite(outbuf, 1, (size_t)outl, fout);
		fwrite(tag, 1, (size_t)taglen, fout);
		chunks++;
		nonce_increment(nonce, nonce_len);
	}

	write_u32(fout, 0);

	fprintf(stderr, "Encrypted: %zu bytes -> %d chunks, algo=%s\n",
	        total_in, chunks, algo_id == ALGO_GCM ? "GCM" : "CCM");

	ret = 1;

cleanup:
	free(inbuf);
	free(outbuf);
	fclose(fin);
	fclose(fout);
	return ret;
}

/*  Decrypt file  */
static int do_decrypt(EVP_CIPHER *cipher, int algo_id, const unsigned char *key,
                      const unsigned char *aad, size_t aadlen,
                      const char *in_path, const char *out_path)
{
	FILE *fin, *fout;
	unsigned char *inbuf = NULL, *outbuf = NULL;
	unsigned char nonce[13], tag[16], hdr_magic[MAGIC_LEN];
	unsigned char file_aad[4096];
	size_t nonce_len, file_aadlen, total_out = 0;
	uint32_t hdr_chunk_size, chunk_len;
	int hdr_algo, hdr_taglen, chunks = 0, outl, ret = 0;

	fin = fopen(in_path, "rb");
	if (!fin) {
		perror(in_path);
		return 0;
	}

	fout = fopen(out_path, "wb");
	if (!fout) {
		perror(out_path);
		fclose(fin);
		return 0;
	}

	/* lire header */
	if (fread(hdr_magic, 1, MAGIC_LEN, fin) != MAGIC_LEN ||
	    memcmp(hdr_magic, MAGIC, MAGIC_LEN) != 0) {
		fprintf(stderr, "Invalid file (bad magic)\n");
		goto cleanup;
	}

	hdr_algo = fgetc(fin);
	hdr_chunk_size = read_u32(fin);
	nonce_len = (size_t)fgetc(fin);

	if (nonce_len < 7 || nonce_len > 13) {
		fprintf(stderr, "Invalid nonce length: %zu\n", nonce_len);
		goto cleanup;
	}

	if (fread(nonce, 1, nonce_len, fin) != nonce_len) {
		fprintf(stderr, "Cannot read nonce\n");
		goto cleanup;
	}

	hdr_taglen = fgetc(fin);
	if (hdr_taglen < 4 || hdr_taglen > 16) {
		fprintf(stderr, "Invalid tag length: %d\n", hdr_taglen);
		goto cleanup;
	}

	file_aadlen = read_u32(fin);
	if (file_aadlen > sizeof(file_aad)) {
		fprintf(stderr, "AAD too large: %zu\n", file_aadlen);
		goto cleanup;
	}

	if (file_aadlen > 0 && fread(file_aad, 1, file_aadlen, fin) != file_aadlen) {
		fprintf(stderr, "Cannot read AAD\n");
		goto cleanup;
	}

	/* verify if AAD matches */
	if (aadlen > 0) {
		if (aadlen != file_aadlen || memcmp(aad, file_aad, aadlen) != 0) {
			fprintf(stderr, "AAD mismatch (provided vs file header)\n");
			goto cleanup;
		}
	}

	if (hdr_algo != algo_id) {
		fprintf(stderr, "Algorithm mismatch: file=%s requested=%s\n",
		        hdr_algo == ALGO_GCM ? "GCM" : "CCM",
		        algo_id == ALGO_GCM ? "GCM" : "CCM");
		goto cleanup;
	}

	inbuf = malloc(hdr_chunk_size + 16);
	outbuf = malloc(hdr_chunk_size);
	if (!inbuf || !outbuf)
		goto cleanup;

	while (1) {
		int ok;

		chunk_len = read_u32(fin);
		if (chunk_len == 0)
			break;

		if (chunk_len > hdr_chunk_size) {
			fprintf(stderr, "Chunk %d too large\n", chunks);
			goto cleanup;
		}

		if (fread(inbuf, 1, chunk_len, fin) != chunk_len)
			goto cleanup;

		if (fread(tag, 1, (size_t)hdr_taglen, fin) != (size_t)hdr_taglen)
			goto cleanup;

		outl = 0;

		if (hdr_algo == ALGO_GCM)
			ok = gcm_dec_chunk(cipher, key, nonce, (chunks == 0) ? file_aad : NULL,
			                   (chunks == 0) ? file_aadlen : 0, inbuf, chunk_len,
			                   outbuf, &outl, tag, hdr_taglen);
		else
			ok = ccm_dec_chunk(cipher, key, nonce, nonce_len,
			                   (chunks == 0) ? file_aad : NULL,
			                   (chunks == 0) ? file_aadlen : 0, inbuf, chunk_len,
			                   outbuf, &outl, tag, hdr_taglen);

		if (!ok) {
			fprintf(stderr, "AUTHENTICATION FAILED chunk %d - file tampered or wrong key!\n", chunks);
			goto cleanup;
		}

		fwrite(outbuf, 1, (size_t)outl, fout);
		total_out += (size_t)outl;
		chunks++;
		nonce_increment(nonce, nonce_len);
	}

	fprintf(stderr, "Decrypted: %d chunks -> %zu bytes, algo=%s\n",
	        chunks, total_out, hdr_algo == ALGO_GCM ? "GCM" : "CCM");

	ret = 1;

cleanup:
	free(inbuf);
	free(outbuf);
	fclose(fin);
	fclose(fout);
	return ret;
}

static void usage(const char *prog)
{
	fprintf(stderr,
	        "Usage:\n"
	        "  %s enc -algo gcm|ccm -K <hex> -iv <hex> [-aad <hex>] [-taglen <n>]\n"
	        "         -in <file> -out <file> [-provider <name>] [-soft]\n\n"
	        "  %s dec -algo gcm|ccm -K <hex> -in <file> -out <file>\n"
	        "         [-iv <hex>] [-aad <hex>] [-provider <name>] [-soft]\n\n"
	        "Options:\n"
	        "  -algo      gcm or ccm (required)\n"
	        "  -K         AES key hex (32/48/64 chars -> 128/192/256 auto)\n"
	        "  -iv        nonce hex (24 chars=12B for GCM, 14-26 chars=7-13B for CCM)\n"
	        "  -aad       additional authenticated data hex (optional)\n"
	        "  -taglen    tag size 4-16 bytes (default: 16)\n"
	        "  -in        input file\n"
	        "  -out       output file\n"
	        "  -provider  stm32prov (AF_ALG or CRYPTODEV)\n"
	        "  -soft      use OpenSSL software instead of hardware\n\n"
	        "Handles files of any size via 60KB chunking with auto-incremented nonce.\n",
	        prog, prog);
}

int main(int argc, char *argv[])
{
	int encrypt = -1, use_soft = 0, taglen = 16, algo_id = 0, i;
	const char *key_hex = NULL, *iv_hex = NULL, *aad_hex = NULL, *algo_str = NULL;
	const char *in_path = NULL, *out_path = NULL;
	const char *provider_name = "stm32prov";

	unsigned char key[32], iv[13], aad[4096];
	size_t keylen = 0, ivlen = 0, aadlen = 0;

	OSSL_PROVIDER *prov_default = NULL, *prov_hw = NULL;
	EVP_CIPHER *cipher = NULL;
	const char *algo_name, *propquery;
	int ret = 1;

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "enc") == 0)
		encrypt = 1;
	else if (strcmp(argv[1], "dec") == 0)
		encrypt = 0;
	else {
		usage(argv[0]);
		return 1;
	}

	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "-algo") == 0 && i + 1 < argc)
			algo_str = argv[++i];
		else if (strcmp(argv[i], "-K") == 0 && i + 1 < argc)
			key_hex = argv[++i];
		else if (strcmp(argv[i], "-iv") == 0 && i + 1 < argc)
			iv_hex = argv[++i];
		else if (strcmp(argv[i], "-aad") == 0 && i + 1 < argc)
			aad_hex = argv[++i];
		else if (strcmp(argv[i], "-taglen") == 0 && i + 1 < argc)
			taglen = atoi(argv[++i]);
		else if (strcmp(argv[i], "-in") == 0 && i + 1 < argc)
			in_path = argv[++i];
		else if (strcmp(argv[i], "-out") == 0 && i + 1 < argc)
			out_path = argv[++i];
		else if (strcmp(argv[i], "-provider") == 0 && i + 1 < argc)
			provider_name = argv[++i];
		else if (strcmp(argv[i], "-soft") == 0)
			use_soft = 1;
	}

	if (!algo_str || !key_hex || !in_path || !out_path) {
		fprintf(stderr, "Missing required args: -algo, -K, -in, -out\n");
		usage(argv[0]);
		return 1;
	}

	/* algo */
	if (strcmp(algo_str, "gcm") == 0)
		algo_id = ALGO_GCM;
	else if (strcmp(algo_str, "ccm") == 0)
		algo_id = ALGO_CCM;
	else {
		fprintf(stderr, "Unknown algo: %s (use gcm or ccm)\n", algo_str);
		return 1;
	}

	/* key */
	if (!hex2bin(key_hex, key, &keylen, 32)) {
		fprintf(stderr, "Bad key\n");
		return 1;
	}

	/* iv - required for encrypt, optional for decrypt (read from file) */
	if (iv_hex) {
		if (!hex2bin(iv_hex, iv, &ivlen, 13)) {
			fprintf(stderr, "Bad IV\n");
			return 1;
		}

		if (algo_id == ALGO_GCM && ivlen != 12) {
			fprintf(stderr, "GCM nonce must be 12 bytes\n");
			return 1;
		}

		if (algo_id == ALGO_CCM && (ivlen < 7 || ivlen > 13)) {
			fprintf(stderr, "CCM nonce must be 7-13 bytes\n");
			return 1;
		}
	}
	else if (encrypt) {
		fprintf(stderr, "Encryption requires -iv\n");
		return 1;
	}

	/* aad */
	if (aad_hex && !hex2bin(aad_hex, aad, &aadlen, 4096)) {
		fprintf(stderr, "Bad AAD\n");
		return 1;
	}

	if (taglen < 4 || taglen > 16) {
		fprintf(stderr, "taglen 4-16\n");
		return 1;
	}

	/* algo name */
	switch (keylen) {
	case 16:
		algo_name = (algo_id == ALGO_GCM) ? "AES-128-GCM" : "AES-128-CCM";
		break;
	case 24:
		algo_name = (algo_id == ALGO_GCM) ? "AES-192-GCM" : "AES-192-CCM";
		break;
	case 32:
		algo_name = (algo_id == ALGO_GCM) ? "AES-256-GCM" : "AES-256-CCM";
		break;
	default:
		fprintf(stderr, "Key must be 16/24/32 bytes\n");
		return 1;
	}

	/* providers */
	prov_default = OSSL_PROVIDER_load(NULL, "default");
	if (!use_soft) {
		prov_hw = OSSL_PROVIDER_load(NULL, provider_name);
		if (!prov_hw) {
			fprintf(stderr, "Cannot load provider '%s'\n", provider_name);
			goto cleanup;
		}

		propquery = "provider=stm32";
	}
	else {
		propquery = "provider=default";
	}

	cipher = EVP_CIPHER_fetch(NULL, algo_name, propquery);
	if (!cipher) {
		fprintf(stderr, "Cannot fetch %s\n", algo_name);
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	if (encrypt)
		ret = do_encrypt(cipher, algo_id, key, iv, ivlen, aad, aadlen, taglen,
		                 in_path, out_path) ? 0 : 1;
	else
		ret = do_decrypt(cipher, algo_id, key, aad, aadlen, in_path, out_path) ? 0 : 1;

cleanup:
	if (cipher)
		EVP_CIPHER_free(cipher);

	if (prov_hw)
		OSSL_PROVIDER_unload(prov_hw);

	if (prov_default)
		OSSL_PROVIDER_unload(prov_default);

	return ret;
}