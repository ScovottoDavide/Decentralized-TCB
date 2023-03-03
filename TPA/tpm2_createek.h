#if !defined(TPM2_CREATEEK_H)
#define TPM2_CREATEEK_H

#include "PEMconvertPub.h"
#include "all_util.h"

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
TSS2_RC tpm2_createek(ESYS_CONTEXT *ectx, uint16_t *ek_handle);
#endif