#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>
#include "createek_util.h"

static bool filter_hierarchy_handles(TPMI_RH_PROVISION hierarchy, tpm2_handle_flags flags);
static bool filter_handles(TPMI_RH_PROVISION *hierarchy, tpm2_handle_flags flags);
bool tpm2_util_string_to_uint32(const char *str, uint32_t *value);
bool tpm2_util_handle_from_optarg(const char *value, TPMI_RH_PROVISION *hierarchy, tpm2_handle_flags flags);
ESYS_TR tpm2_tpmi_hierarchy_to_esys_tr(TPMI_RH_PROVISION inh);
TSS2_RC tpm2_from_tpm_public(ESYS_CONTEXT *esys_context, TPM2_HANDLE tpm_handle, ESYS_TR optional_session1, ESYS_TR optional_session2, ESYS_TR optional_session3, ESYS_TR *object);
TSS2_RC tpm2_util_sys_handle_to_esys_handle(ESYS_CONTEXT *context, TPM2_HANDLE sys_handle, ESYS_TR *esys_handle);
TSS2_RC tpm2_util_object_load2(ESYS_CONTEXT *ctx, const char *objectstr, const char *auth, bool do_auth, tpm2_loaded_object *outobject, bool is_restricted_pswd_session, tpm2_handle_flags flags);
TSS2_RC tpm2_util_object_load(ESYS_CONTEXT *ctx, const char *objectstr, tpm2_loaded_object *outobject, tpm2_handle_flags flags);

/*TSS2_RC tpm2_get_capability(ESYS_CONTEXT *esys_context, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, TPM2_CAP capability, UINT32 property, UINT32 property_count, TPMI_YES_NO *more_data, TPMS_CAPABILITY_DATA **capability_data);
TSS2_RC tpm2_capability_get(ESYS_CONTEXT *ectx, TPM2_CAP capability, UINT32 property, UINT32 count, TPMS_CAPABILITY_DATA **capability_data);
TSS2_RC tpm2_capability_find_vacant_persistent_handle(ESYS_CONTEXT *ctx, bool is_platform, TPMI_DH_PERSISTENT *vacant);*/

TSS2_RC tpm2_quote_internal(ESYS_CONTEXT *esys_context, tpm2_loaded_object *quote_obj,
    TPMT_SIG_SCHEME *in_scheme, TPM2B_DATA *qualifying_data,
    TPML_PCR_SELECTION *pcr_select, TPM2B_ATTEST **quoted,
    TPMT_SIGNATURE **signature);
