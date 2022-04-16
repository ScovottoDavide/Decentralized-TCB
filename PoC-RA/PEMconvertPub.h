#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#include <openssl/rsa.h>
#else
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#endif
#include <tss2/tss2_esys.h>

EVP_PKEY *convert_pubkey_RSA(TPMT_PUBLIC *public);
static bool tpm2_convert_pubkey_bio(TPMT_PUBLIC *public, BIO *bio);
static bool tpm2_convert_pubkey_ssl(TPMT_PUBLIC *public, const char *path);
bool tpm2_convert_pubkey_save(TPM2B_PUBLIC *public, const char *path);
