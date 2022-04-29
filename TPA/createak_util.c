#include "createak_util.h"

static bool filter_hierarchy_handles(TPMI_RH_PROVISION hierarchy, tpm2_handle_flags flags) {

    switch (hierarchy) {
    case TPM2_RH_OWNER:
        if (!(flags & TPM2_HANDLE_FLAGS_O)) {
            printf("Unexpected handle - TPM2_RH_OWNER\n");
            return false;
        }
        break;
    case TPM2_RH_PLATFORM:
        if (!(flags & TPM2_HANDLE_FLAGS_P)) {
            printf("Unexpected handle - TPM2_RH_PLATFORM\n");
            return false;
        }
        break;
    case TPM2_RH_ENDORSEMENT:
        if (!(flags & TPM2_HANDLE_FLAGS_E)) {
            printf("Unexpected handle - TPM2_RH_ENDORSEMENT\n");
            return false;
        }
        break;
    case TPM2_RH_NULL:
        if (!(flags & TPM2_HANDLE_FLAGS_N)) {
            printf("Unexpected handle - TPM2_RH_NULL\n");
            return false;
        }
        break;
    case TPM2_RH_LOCKOUT:
        if (!(flags & TPM2_HANDLE_FLAGS_L)) {
            printf("Unexpected handle - TPM2_RH_LOCKOUT\n");
            return false;
        }
        break;
    default: //If specified a random offset to the permanent handle range
        if (flags == TPM2_HANDLE_ALL_W_NV || flags == TPM2_HANDLE_FLAGS_NONE) {
            return true;
        }
        return false;
    }

    return true;
}

static bool filter_handles(TPMI_RH_PROVISION *hierarchy, tpm2_handle_flags flags) {

    TPM2_RH range = *hierarchy & TPM2_HR_RANGE_MASK;

    /*
     * if their is no range, then it could be NV or PCR, use flags
     * to figure out what it is.
     */
    if (range == 0) {
        if (flags & TPM2_HANDLE_FLAGS_NV) {
            *hierarchy += TPM2_HR_NV_INDEX;
            range = *hierarchy & TPM2_HR_RANGE_MASK;
        } else if (flags & TPM2_HANDLE_FLAGS_PCR) {
            *hierarchy += TPM2_HR_PCR;
            range = *hierarchy & TPM2_HR_RANGE_MASK;
        } else {
            printf("Implicit indices are not supported.\n");
            return false;
        }
    }

    /* now that we have fixed up any non-ranged handles, check them */
    if (range == TPM2_HR_NV_INDEX) {
        if (!(flags & TPM2_HANDLE_FLAGS_NV)) {
            printf("NV-Index handles are not supported by this command.\n");
            return false;
        }
        if (*hierarchy < TPM2_NV_INDEX_FIRST
                || *hierarchy > TPM2_NV_INDEX_LAST) {
            printf("NV-Index handle is out of range.\n");
            return false;
        }
        return true;
    } else if (range == TPM2_HR_PCR) {
        if (!(flags & TPM2_HANDLE_FLAGS_PCR)) {
            printf("PCR handles are not supported by this command.\n");
            return false;
        }
        /* first is 0 so no possible way unsigned is less than 0, thus no check */
        if (*hierarchy > TPM2_PCR_LAST) {
            printf("PCR handle out of range.\n");
            return false;
        }
        return true;
    } else if (range == TPM2_HR_TRANSIENT) {
        if (!(flags & TPM2_HANDLES_FLAGS_TRANSIENT)) {
            printf("Transient handles are not supported by this command.\n");
            return false;
        }
        return true;
    } else if (range == TPM2_HR_PERMANENT) {
        return filter_hierarchy_handles(*hierarchy, flags);
    } else if (range == TPM2_HR_PERSISTENT) {
        if (!(flags & TPM2_HANDLES_FLAGS_PERSISTENT)) {
            printf("Persistent handles are not supported by this command.\n");
            return false;
        }
        if (*hierarchy < TPM2_PERSISTENT_FIRST
                || *hierarchy > TPM2_PERSISTENT_LAST) {
            printf("Persistent handle out of range.\n");
            return false;
        }
        return true;
    }

    /* else its a session flag and shouldn't use this interface */
    return false;
}

bool tpm2_util_string_to_uint32(const char *str, uint32_t *value) {
  char *endptr;

  if(str == NULL || *str == '\0')
    return false;
  /* clear errno before the call, should be 0 afterwards */
  unsigned long int tmp = strtoul(str, &endptr, 0);
  if(tmp > UINT32_MAX)
    return false;
  if(*endptr != '\0')
    return false;

  *value = (uint32_t) tmp;
  return true;
}

bool tpm2_util_handle_from_optarg(const char *value, TPMI_RH_PROVISION *hierarchy, tpm2_handle_flags flags) {

  if(!value || !value[0]){
    return false;
  }

  if((flags & TPM2_HANDLE_FLAGS_NV) && (flags & TPM2_HANDLE_FLAGS_PCR)) {
      printf("Cannot specify NV and PCR index together\n");
      return false;
  }

  *hierarchy = 0;
  // handle only hex handles
  bool result = true;
  if(!*hierarchy){
    result = tpm2_util_string_to_uint32(value, hierarchy);
  }

  if(!result){
    printf("Error while converting hex handle (tpm2_util_handle_from_optarg)\n");
    return false;
  }

  bool res = filter_handles(hierarchy, flags);
  if(!res) {
    printf("Unknown or unsupported handle, got \"%s\"\n", value);
  }
  return res;
}

ESYS_TR tpm2_tpmi_hierarchy_to_esys_tr(TPMI_RH_PROVISION inh) {

    switch (inh) {
    case TPM2_RH_OWNER:
        return ESYS_TR_RH_OWNER;
    case TPM2_RH_PLATFORM:
        return ESYS_TR_RH_PLATFORM;
    case TPM2_RH_ENDORSEMENT:
        return ESYS_TR_RH_ENDORSEMENT;
    case TPM2_RH_NULL:
        return ESYS_TR_RH_NULL;
    case TPM2_RH_LOCKOUT:
        return ESYS_TR_RH_LOCKOUT;
    }
    return ESYS_TR_NONE;
}

TSS2_RC tpm2_from_tpm_public(ESYS_CONTEXT *esys_context, TPM2_HANDLE tpm_handle, ESYS_TR optional_session1, ESYS_TR optional_session2, ESYS_TR optional_session3, ESYS_TR *object) {

    TSS2_RC rval = Esys_TR_FromTPMPublic(esys_context, tpm_handle,
            optional_session1, optional_session2, optional_session3, object);
    if (rval != TSS2_RC_SUCCESS) {
        printf("(tpm2_from_tpm_public) Erro in Esys_TR_FromTPMPublic\n");
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

TSS2_RC tpm2_util_sys_handle_to_esys_handle(ESYS_CONTEXT *context, TPM2_HANDLE sys_handle, ESYS_TR *esys_handle) {

  ESYS_TR h = tpm2_tpmi_hierarchy_to_esys_tr(sys_handle);
  if(h != ESYS_TR_NONE){
    *esys_handle = h;
    return TSS2_RC_SUCCESS;
  }

  return tpm2_from_tpm_public(context, sys_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, esys_handle);
}

TSS2_RC tpm2_util_object_load2(ESYS_CONTEXT *ctx, const char *objectstr, const char *auth, bool do_auth, tpm2_loaded_object *outobject, bool is_restricted_pswd_session, tpm2_handle_flags flags){
  // is_restricted_pswd_session==false --> skip
  // do_auth==false --> skip

  if (!objectstr) {
    printf("object string is empty\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  // ctx.ek.ctx_arg is not a file --> manage handle (it's the -c option)
  // Convert a raw handle

  TPMI_RH_PROVISION handle;
  bool res = tpm2_util_handle_from_optarg(objectstr, &handle, flags);
  if(res) {
    outobject->handle = handle;
    outobject->path = NULL;
    return tpm2_util_sys_handle_to_esys_handle(ctx, outobject->handle, &outobject->tr_handle);
  }

  printf("(tpm2_util_object_load2) Cannot make senso of object context \"%s\"\n", objectstr);
  return TSS2_ESYS_RC_BAD_VALUE;
}

TSS2_RC tpm2_util_object_load(ESYS_CONTEXT *ctx, const char *objectstr, tpm2_loaded_object *outobject, tpm2_handle_flags flags){
  return tpm2_util_object_load2(ctx, objectstr, NULL, false, outobject, false, flags);
}