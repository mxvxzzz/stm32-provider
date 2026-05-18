
#ifndef STM32_NAMES_H
#define STM32_NAMES_H

/* 
 * Names OIDs of algorithmes supported
 *
 * Convention OpenSSL : "NOM_PRINCIPAL:ALIAS:OID"
 * Source : openssl/providers/implementations/include/prov/names.h
*/

/* Digests */
#define STM32_NAME_SHA1      "SHA1:SHA-1:SSL3-SHA1:1.3.14.3.2.26"
#define STM32_NAME_SHA2_224  "SHA2-224:SHA-224:SHA224:2.16.840.1.101.3.4.2.4"
#define STM32_NAME_SHA2_256  "SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1"
#define STM32_NAME_SHA2_384  "SHA2-384:SHA-384:SHA384:2.16.840.1.101.3.4.2.2"
#define STM32_NAME_SHA2_512  "SHA2-512:SHA-512:SHA512:2.16.840.1.101.3.4.2.3"
#define STM32_NAME_SHA3_224  "SHA3-224:2.16.840.1.101.3.4.2.7"
#define STM32_NAME_SHA3_256  "SHA3-256:2.16.840.1.101.3.4.2.8"
#define STM32_NAME_SHA3_384  "SHA3-384:2.16.840.1.101.3.4.2.9"
#define STM32_NAME_SHA3_512  "SHA3-512:2.16.840.1.101.3.4.2.10"

/* MACs */
#define STM32_NAME_HMAC         "HMAC"

/* Prpts */
#define STM32_PROV_PROPS        "provider=stm32"

#endif /* STM32_NAMES_H */