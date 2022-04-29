#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>
#include "all_util.h"

#define APPEND_CAPABILITY_INFORMATION(capability, field, subfield, max_count) \
    if (fetched_data->data.capability.count > max_count - property_count) { \
        fetched_data->data.capability.count = max_count - property_count; \
    } \
\
    memmove(&(*capability_data)->data.capability.field[property_count], \
            fetched_data->data.capability.field, \
            fetched_data->data.capability.count * sizeof(fetched_data->data.capability.field[0])); \
    property_count += fetched_data->data.capability.count; \
\
    (*capability_data)->data.capability.count = property_count; \
\
    if (more_data && property_count < count && fetched_data->data.capability.count) { \
        property = (*capability_data)->data.capability.field[property_count - 1]subfield + 1; \
    } else { \
        more_data = false; \
    }

TSS2_RC tpm2_public_init(const char *alg_details, const char *name_halg, TPMA_OBJECT def_attrs, TPM2B_PUBLIC *public);
tpm2_session_data* tpm2_session_data_new(TPM2_SE type);
void tpm2_session_set_authhash(tpm2_session_data *data, TPMI_ALG_HASH auth_hash);
TSS2_RC tpm2_session_open(ESYS_CONTEXT *context, tpm2_session_data *data, tpm2_session **session);

TSS2_RC tpm2_start_auth_session(ESYS_CONTEXT *esys_context, ESYS_TR tpm_key,
        ESYS_TR bind, const TPM2B_NONCE *nonce_caller, TPM2_SE session_type,
        const TPMT_SYM_DEF *symmetric, TPMI_ALG_HASH auth_hash,
        ESYS_TR *session_handle);

TSS2_RC tpm2_sess_set_atributes(ESYS_CONTEXT *esys_context, ESYS_TR session, TPMA_SESSION flags, TPMA_SESSION mask);
TSS2_RC start_auth_session(tpm2_session *session);
ESYS_TR tpm2_session_get_handle(tpm2_session *session);
const TPM2B_AUTH *tpm2_session_get_auth_value(tpm2_session *session);
void tpm2_session_set_auth_value(tpm2_session *session, TPM2B_AUTH *auth);
TSS2_RC tpm2_auth_util_get_shandle(ESYS_CONTEXT *ectx, ESYS_TR object, tpm2_session *session, ESYS_TR *out);

TSS2_RC tpm2_util_object_load_auth(ESYS_CONTEXT *ctx, const char *objectstr,const char *auth,
  tpm2_loaded_object *outobject,bool is_restricted_pswd_session, tpm2_handle_flags flags);

TSS2_RC tpm2_util_object_load_auth(ESYS_CONTEXT *ctx, const char *objectstr,const char *auth,
  tpm2_loaded_object *outobject,bool is_restricted_pswd_session, tpm2_handle_flags flags);

TSS2_RC tpm2_auth_util_from_optarg(ESYS_CONTEXT *ectx, const char *password, tpm2_session **session, bool is_restricted);

void tpm2_session_free(tpm2_session **session);
TSS2_RC tpm2_flush_context(ESYS_CONTEXT *esys_context, ESYS_TR flush_handle);
TSS2_RC tpm2_session_close(tpm2_session **s);

TSS2_RC tpm2_get_capability(ESYS_CONTEXT *esys_context, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, TPM2_CAP capability, UINT32 property, UINT32 property_count, TPMI_YES_NO *more_data, TPMS_CAPABILITY_DATA **capability_data);
TSS2_RC tpm2_capability_get(ESYS_CONTEXT *ectx, TPM2_CAP capability, UINT32 property, UINT32 count, TPMS_CAPABILITY_DATA **capability_data);
TSS2_RC tpm2_capability_find_vacant_persistent_handle(ESYS_CONTEXT *ctx, bool is_platform, TPMI_DH_PERSISTENT *vacant);
