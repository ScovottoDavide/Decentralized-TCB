#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>

#define TPM2B_SENSITIVE_CREATE_EMPTY_INIT { \
           .sensitive = { \
                .data = {   \
                    .size = 0 \
                }, \
                .userAuth = {   \
                    .size = 0 \
                } \
            } \
    }

static TSS2_RC init_ek_public(TPM2B_PUBLIC *public);
TSS2_RC tpm2_createek(ESYS_CONTEXT *ectx);
