# STM32MPU Provider

Experimental OpenSSL 3 provider implementing digest algorithms through the Linux AF_ALG and Cryptodev interface. In OpenSSL terms, a provider is a unit of code that offers implementations for operations such as digests, ciphers, signatures, and more.

Here is a overviweuw of the CryptoAPI architecture, from User space to hardware

## CryptoAPI overview with ST Provider

![Architecture Crypto](./images/drawio.svg)

## Project Layout & Components

This project uses:
- A custom OpenSSL provider module: `stm32_provider.so`
- Implementations through `AF_ALG` and `Cryptodev`
- `libprov` : A helper library used for provider-side error reporting
- `include/err.h` + `err.c` : Provides provider-specific error handling and reason strings
- `bear` : A command-line tool used to generate `compile_commands.json` for editor integration
---

Here is a diagram showing the internal components of the provider:

### Architecture Provider STM32MPU

![Architecture Crypto](./images/stprovider.svg)

### Internal Workflow

- **Entry Point (`prov.c`):** The main entry point that registers the provider and sets up the OpenSSL dispatch tables for the supported operations (Digests, Ciphers, etc.).

- **Operation Layer (`digest/`, `cipher/`):** Implements the standard OpenSSL interfaces (`newctx`, `init`, `update`, `final`) to dispatch algorithms cleanly.

- **Precompilation Switch:** A build-time configuration flag that selects the targeted Linux kernel API backend.

- **Kernel Backends:** Depending on the precompilation switch, the code utilizes dedicated source files tailored for each interface—either using Linux `AF_ALG` (e.g., `*_afalg.c`) or `Cryptodev` with `/dev/crypto` (e.g., `*_cryptodev.c`) to bridge operations like digests, ciphers, or HMACs with the kernel.

- **Hardware Acceleration:** The Linux Crypto API routes these requests directly to the dedicated **STM32 HASH or CRYP Processors** via their respective drivers.

## Supported digests

Currently implemented:

- SHA-1
- SHA-224
- SHA-256
- SHA-384
- SHA-512
- SHA3-256
- SHA3-384
- SHA3-512

---

## How to load the provider

OpenSSL command-line tools accept provider options such as -provider and -provider-path, and openssl list can display loaded providers, provider versions, and available algorithms.

- List loaded providers

  `openssl list -providers`
- Load this provider from the current directory

  `openssl list -provider-path . -provider stm32_provider -providers`
- List digest algorithms exposed by this provider

  `openssl list -provider-path . -provider stm32_provider -digest-algorithms`
- Verbose provider information

  `openssl list -provider-path . -provider stm32_provider -providers -verbose`

- Set the environment variable `OPENSSL_MODULES` to the directory containing the provider shared library without `-provider-path`.
  Example:

  `export OPENSSL_MODULES=$HOME/your_module_directory`

- Compute a SHA256 digest with this provider

  `openssl dgst -provider stm32_provider -propquery "provider=stm32" -sha256 /file.txt`

- Benchmark using openssl speed of SHA3-512 with this provider

  `openssl speed -provider stm32_provider -propquery "provider=stm32" -evp sha3-512`

- You can also use options such as `-seconds`, `-elapsed`, and `-bytes` to customize the benchmark. For more details, refer to the `openssl speed` documentation.

  `openssl speed -seconds 10 -elapsed -bytes 8192 -provider stm32_provider -propquery "provider=stm32" sha256`

## Benchmark Results
You can view the latest performance reports for SHA-1, SHA-256, and SHA-512 here:

👉 [View Benchmark Report](https://mxvxzzz.github.io/stm32-provider/bench/index.html)