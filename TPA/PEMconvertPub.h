#if !defined(PEMCONVERTPUB_H)
#define PEMCONVERTPUB_H

#include "all_util.h"

EVP_PKEY *convert_pubkey_RSA(TPMT_PUBLIC *public);
static bool tpm2_convert_pubkey_bio(TPMT_PUBLIC *public, BIO *bio);
static bool tpm2_convert_pubkey_ssl(TPMT_PUBLIC *public, const char *path);
bool tpm2_convert_pubkey_save(TPM2B_PUBLIC *public, const char *path);
#endif