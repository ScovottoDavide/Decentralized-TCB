#if !defined(PCR9EXTEND_H)
#define PCR9EXTEND_H

#include "createak_util.h"
#include "all_util.h"

typedef struct tpm2_pcr_digest_spec tpm2_pcr_digest_spec;
struct tpm2_pcr_digest_spec {
    TPML_DIGEST_VALUES digests;
    TPMI_DH_PCR pcr_index;
};

bool openAKPub(const char *path, unsigned char **akPub);
// Using OpenSSL direct APIs for computing the Digest --> NOT RECOMMENDED!!
bool computeDigest(unsigned char* akPub, const char* sha_alg, unsigned char **digest);
// Using OpenSSL higher APIs for computing the Digest
int computeDigestEVP(unsigned char* akPub, const char* sha_alg, unsigned char *digest);

int tpm2_util_hex_to_byte_structure(const char *input_string, UINT16 *byte_length, BYTE *byte_buffer);
TSS2_RC ExtendPCR9(ESYS_CONTEXT *ectx, const char* halg);
#endif