# STM32 OpenSSL Provider

In OpenSSL terms, a provider is a unit of code that offers implementations for cryptographic operations such as digests, ciphers, signatures, and more.

STM32 Provider offloads cryptographic operations for security peripherals embedded in ST MPUs, through the Linux AF_ALG and Cryptodev.

Here is a overviweuw of the CryptoAPI architecture, from User space to hardware :

## CryptoAPI overview with STM32 Provider

![Architecture Crypto](./images/drawio.svg)

## Project Layout & Components

This project uses:
- A custom OpenSSL provider module: `stm32prov.so`
- Implementations through `AF_ALG` and `Cryptodev`
- `libprov` : A helper library used for provider-side error reporting
- `include/err.h` + `err.c` : Provides provider-specific error handling and reason strings
---

### Internal Workflow

- **Entry Point (`prov.c`):** The main entry point that registers the provider and sets up the OpenSSL dispatch tables for the supported operations (Digests, Ciphers, etc.).

- **Operation Layer (`digest/`, `hmac/`, `cipher/`,`aead/`):** Implements the standard OpenSSL interfaces (`newctx`, `init`, `update`, `final`) to dispatch algorithms.

- **Precompilation Switch:** A build-time configuration flag that selects the targeted Linux kernel API backend.

- **Kernel Backends:** Depending on the precompilation switch, the code utilizes dedicated source files tailored for each interface—either using Linux `AF_ALG` (e.g., `*_afalg.c`) or `Cryptodev` with `/dev/crypto` (e.g., `*_devcrypto.c`) to bridge operations like digests, ciphers, or HMACs with the kernel.

- **Hardware Acceleration:** The Linux Crypto API routes these requests directly to the dedicated **STM32 HASH or CRYP Processors** via their respective drivers.

## Implemented algorithms

| Category    | Algorithms |
|-------------|------------|
| Digest      | SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512 |
| HMAC        | HMAC-SHA-1, HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512, HMAC-SHA3-256, HMAC-SHA3-384, HMAC-SHA3-512 |
| Cipher AES  | AES-128-ECB, AES-192-ECB, AES-256-ECB, AES-128-CBC, AES-192-CBC, AES-256-CBC, AES-128-CTR, AES-192-CTR, AES-256-CTR |
| Cipher AEAD | AES-128-GCM, AES-192-GCM, AES-256-GCM, AES-128-CCM, AES-192-CCM, AES-256-CCM |

---

## How to load the provider

OpenSSL command-line tools accept provider options such as -provider and -provider-path, and openssl list can display loaded providers, provider versions, and available algorithms.

- List loaded providers

  `openssl list -providers`
- Load this provider from the current directory

  `openssl list -provider-path . -provider stm32prov -providers`
- List digest algorithms exposed by this provider

  `openssl list -provider-path . -provider stm32prov -digest-algorithms`
- Verbose provider information

  `openssl list -provider-path . -provider stm32prov -providers -verbose`

- Set the environment variable `OPENSSL_MODULES` to the directory containing the provider shared library without `-provider-path`.
  Example:

  `export OPENSSL_MODULES=$HOME/your_module_directory`

## Usage examples

### Digest :

- Compute a SHA256 digest with STM32 provider

  `openssl dgst -provider stm32prov -propquery "provider=stm32" -sha256 /file.txt`

- Benchmark using openssl speed of SHA3-512 with STM32 provider

  `openssl speed -provider stm32prov -propquery "provider=stm32" -evp sha3-512`

- You can also use options such as `-seconds`, `-elapsed`, and `-bytes` to customize the benchmark. 

  `openssl speed -seconds 10 -elapsed -bytes 8192 -provider stm32prov -propquery "provider=stm32" sha256`

  For more details, refer to the `openssl speed` documentation.

  👉 https://docs.openssl.org/3.1/man1/openssl-speed/

### HMAC
  
 - Create the input file :

  `echo "This is a secret message to authenticate." > data.bin`

 - Generate a key :

  `KEY_HEX=$(openssl rand -hex 32)`

 - Compute the HMAC :

  `openssl mac -digest SHA256 -macopt hexkey:$KEY_HEX -in data.bin -provider stm32prov -propquery "provider=stm32" HMAC`

### CIPHER AES ECB/CBC/CTR

- Create the input file

  `echo "This is a test message" > /tmp/data.bin`

- Encrypt and decrypt a file using AES-192-ECB

  For AES-192-ECB, the key size is 24 bytes (48 characters in hexa).

  Encryption:

  `openssl enc -aes-192-ecb -provider stm32prov -provider default -propquery "provider=stm32" -K 00112233445566778899aabbccddeeff0001020304050607 -in /tmp/data.bin -out /tmp/enc_ecb.bin`

  Decryption:

  `openssl enc -d -aes-192-ecb -provider stm32prov -provider default -propquery "provider=stm32" -K 00112233445566778899aabbccddeeff0001020304050607 -in /tmp/enc_ecb.bin -out /tmp/dec_ecb.bin`

  Verify the result:

  `diff /tmp/data.bin /tmp/dec_ecb.bin && echo "OK" || echo "ERROR"`

- Encrypt and decrypt a file using AES-128-CBC

  For AES-128-CBC, the key size is 16 bytes, (32 characters in hexa).
  The IV size is 16 bytes.

Encryption:

  `openssl enc -aes-128-cbc -provider stm32prov -provider default -propquery "provider=stm32" -K 00112233445566778899aabbccddeeff -iv 0102030405060708090a0b0c0d0e0f10 -in /tmp/data.bin -out /tmp/enc_cbc.bin`

  Decryption:

  `openssl enc -d -aes-128-cbc -provider stm32prov -provider default -propquery "provider=stm32" -K 00112233445566778899aabbccddeeff -iv 0102030405060708090a0b0c0d0e0f10 -in /tmp/enc_cbc.bin -out /tmp/dec_cbc.bin`

  Verify the result:

  `diff /tmp/data.bin /tmp/dec_cbc.bin && echo "OK" || echo "ERROR"`

- Encrypt and decrypt a file using AES-256-CTR

  For AES-256-CTR, the key size is 32 bytes, (64 characters hexa).  

  Generate a random key and IV:

  `export KEY=$(openssl rand -hex 32)`

  `export IV=$(openssl rand -hex 16)`

  Encryption:

  `openssl enc -aes-256-ctr -provider stm32prov -provider default -propquery "provider=stm32" -K $KEY -iv $IV -in /tmp/data.bin -out /tmp/enc_ctr.bin`

  Decryption:

  `openssl enc -d -aes-256-ctr -provider stm32prov -provider default -propquery "provider=stm32" -K $KEY -iv $IV -in /tmp/enc_ctr.bin -out /tmp/dec_ctr.bin`

  Verify the result:

  `diff /tmp/data.bin /tmp/dec_ctr.bin && echo "OK" || echo "ERROR"`

### CIPHER AEAD GCM/CCM

  The `openssl enc` command does not support AEAD ciphers such as AES-GCM or AES-CCM. OpenSSL explicitly blocks these modes in the `enc` tool because streaming CLI output cannot securely validate authentication tags before data is processed, and incorrect nonce or key reuse can lead to severe security failures.
  

  See the OpenSSL documentation chapter `SUPPORTED CIPHERS` for details:

  - [`openssl enc` notes](https://docs.openssl.org/3.3/man1/openssl-enc/#notes)

  To handle AEAD modes, OpenSSL EVP provide native support.
  
  In this project, AEAD operations are handled with the dedicated `stmaead` tool.

  For detailed usage and validation examples, refer to the following documentation :

👉 [`aead/tools/stmaead.md`](aead/tools/stmaead.md)

## Benchmark Results on STM32MP257-EV1

  See the latest performance reports:

	- **Digest benchmarks**: SHA-1, SHA-256, and SHA-512

	- **Cipher benchmarks**: AES ECB/CBC/CTR (128/192/256)

👉 [View Benchmark Reports](https://mxvxzzz.github.io/stm32mpu-benchmarks/)
