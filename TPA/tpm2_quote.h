#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>

typedef struct tpm2_algorithm tpm2_algorithm;
struct tpm2_algorithm {
    int count;
    TPMI_ALG_HASH alg[TPM2_NUM_PCR_BANKS];
};

bool pcr_parse_list(const char *str, size_t len, TPMS_PCR_SELECTION *pcr_select);
bool pcr_parse_selections(const char *arg, TPML_PCR_SELECTION *pcr_select);
bool read_nonce_from_file(const char *input, UINT16 *len, BYTE *buffer);
TSS2_RC pcr_get_banks(ESYS_CONTEXT *esys_context, TPMS_CAPABILITY_DATA *capability_data, tpm2_algorithm *algs);
TSS2_RC tpm2_public_to_scheme(ESYS_CONTEXT *ectx, ESYS_TR key, TPMI_ALG_PUBLIC *type, TPMT_SIG_SCHEME *sigscheme);
//tpm2_alg_util_get_signature_scheme
TSS2_RC tpm2_get_signature_scheme(ESYS_CONTEXT *ectx, ESYS_TR key_handle, TPMI_ALG_HASH *halg, TPMI_ALG_SIG_SCHEME sig_scheme, TPMT_SIG_SCHEME *scheme);

// tpm2_quote_internal in createak_util.h --> to fix dependencies!!!!!!!!!

TSS2_RC tpm2_quote(ESYS_CONTEXT *esys_ctx);
