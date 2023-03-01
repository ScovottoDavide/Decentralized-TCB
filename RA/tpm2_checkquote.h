#if !defined( TPM2_CHECKQUOTE_H )
#define TPM2_CHECKQUOTE_H

#include "common.h"

#define BUFFER_SIZE(type, field) (sizeof((((type *)NULL)->field)))
#define TPM2B_TYPE_INIT(type, field) { .size = BUFFER_SIZE(type, field), }

#define ARRAY_LEN(x) sizeof(sizeof(x) / sizeof((x)[0]))

TSS2_RC get_internal_attested_data(TPM2B_ATTEST *quoted, TPMS_ATTEST *attest);
bool tpm2_openssl_hash_compute_data(TPMI_ALG_HASH halg, BYTE *buffer, UINT16 length, TPM2B_DIGEST *digest);
bool calculate_pcr_digest(unsigned char *pcr10_sha256, unsigned char *pcr10_sha1, unsigned char *pcr9_sha256, unsigned char *pcr9_sha1,
                            TPMI_ALG_HASH hash_alg, TPM2B_DIGEST *digest);

bool tpm2_public_load_pkey(const char *path, EVP_PKEY **pkey);
bool tpm2_util_verify_digests(TPM2B_DIGEST *quoteDigest, TPM2B_DIGEST *pcr_digest);
bool verify(void);

bool tpm2_checkquote(TO_SEND TpaData, NONCE_BLOB nonce_blob, AK_FILE_TABLE *ak_table, int nodes_number, unsigned char *pcr10_sha256, unsigned char *pcr10_sha1,
                    unsigned char *pcr9_sha256, unsigned char *pcr9_sha1);

#endif