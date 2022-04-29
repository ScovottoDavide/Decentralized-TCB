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
TSS2_RC tpm2_quote(ESYS_CONTEXT *esys_ctx);