#include "createek_util.h"

TSS2_RC tpm2_public_init(const char *alg_details, const char *name_halg, TPMA_OBJECT def_attrs, TPM2B_PUBLIC *public){

  memset(public, 0, sizeof(*public));

  if(strcmp(alg_details, "rsa2048:aes128cfb"))
    return TSS2_ESYS_RC_BAD_VALUE;

  /* Set the hashing algorithm used for object name */
  if(!strcmp("sha256", name_halg))
    public->publicArea.nameAlg = TPM2_ALG_SHA256;
  else public->publicArea.nameAlg = TPM2_ALG_ERROR;

  if(public->publicArea.nameAlg == TPM2_ALG_ERROR){
    printf("Invalid name hashing algorithm, got \"%s\"", name_halg);
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  /* Set the specified attributes */
  public->publicArea.type = TPM2_ALG_RSA;
  public->publicArea.objectAttributes = def_attrs;
  public->size = 0;
  public->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
  public->publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
  public->publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
  public->publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
  public->publicArea.parameters.rsaDetail.keyBits = 2048;
  public->publicArea.parameters.rsaDetail.exponent = 0;


  return TSS2_RC_SUCCESS;
}

tpm2_session_data* tpm2_session_data_new(TPM2_SE type){
  tpm2_session_data *d = calloc(1, sizeof(tpm2_session_data));

  if(d){
    d->symmetric.algorithm = TPM2_ALG_NULL;
    d->key = ESYS_TR_NONE;
    d->bind = ESYS_TR_NONE;
    d->session_type = type;
    d->auth_hash = TPM2_ALG_SHA256;
  }
  return d;
}

void tpm2_session_set_authhash(tpm2_session_data *data, TPMI_ALG_HASH auth_hash){
  data->auth_hash = auth_hash;
}

TSS2_RC tpm2_session_open(ESYS_CONTEXT *context, tpm2_session_data *data, tpm2_session **session){

  tpm2_session *s = calloc(1, sizeof(tpm2_session));
  if(!s){
    free(data);
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  s->input = data;
  s->internal.ectx = context;

  if(!context){
    s->output.session_handle = ESYS_TR_PASSWORD;
    *session = s;
    return TSS2_RC_SUCCESS;
  }

  TSS2_RC res = start_auth_session(s);
  if(res != TSS2_RC_SUCCESS){
    tpm2_session_free(&s);
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  *session = s;
  return TSS2_RC_SUCCESS;
}

TSS2_RC tpm2_start_auth_session(ESYS_CONTEXT *esys_context, ESYS_TR tpm_key,
        ESYS_TR bind, const TPM2B_NONCE *nonce_caller, TPM2_SE session_type,
        const TPMT_SYM_DEF *symmetric, TPMI_ALG_HASH auth_hash,
        ESYS_TR *session_handle){

  TSS2_RC res = Esys_StartAuthSession(esys_context, tpm_key, bind,
                                      ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, nonce_caller, session_type,
                                      symmetric, auth_hash, session_handle);
  if(res != TSS2_RC_SUCCESS){
    printf("Error in Esys_StartAuthSession (tpm2_start_auth_session)\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  return TSS2_RC_SUCCESS;
}

TSS2_RC tpm2_sess_set_atributes(ESYS_CONTEXT *esys_context, ESYS_TR session, TPMA_SESSION flags, TPMA_SESSION mask){

  TSS2_RC res = Esys_TRSess_SetAttributes(esys_context, session, flags, mask);
  if(res != TSS2_RC_SUCCESS){
    printf("Error while setting session attributes (tpm2_sess_set_atributes)\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  return TSS2_RC_SUCCESS;
}

TSS2_RC start_auth_session(tpm2_session *session){
  tpm2_session_data *d = session->input;

  TPM2B_NONCE *nonce = session->input->nonce_caller.size > 0 ? &session->input->nonce_caller : NULL;

  TSS2_RC res = tpm2_start_auth_session(session->internal.ectx, d->key, d->bind, nonce,
                                        d->session_type, &d->symmetric, d->auth_hash,
                                        &session->output.session_handle);

  if(res != TSS2_RC_SUCCESS){
    return res;
  }

  if(d->attrs){
    res = tpm2_sess_set_atributes(session->internal.ectx, session->output.session_handle, d->attrs, 0xff);
    if(res != TSS2_RC_SUCCESS){
      // TODO free
      return res;
    }
  }

  return TSS2_RC_SUCCESS;
}

ESYS_TR tpm2_session_get_handle(tpm2_session *session) {
    return session->output.session_handle;
}

const TPM2B_AUTH *tpm2_session_get_auth_value(tpm2_session *session) {
    return &session->input->auth_data;
}

void tpm2_session_set_auth_value(tpm2_session *session, TPM2B_AUTH *auth){
  if(auth == NULL){
    session->input->auth_data.size = 0;
    memset(session->input->auth_data.buffer, 0xBA, sizeof(session->input->auth_data.buffer));
  }else {
    memcpy(&session->input->auth_data, auth, sizeof(*auth));
  }
}

TSS2_RC tpm2_auth_util_get_shandle(ESYS_CONTEXT *ectx, ESYS_TR object, tpm2_session *session, ESYS_TR *out){

  *out = tpm2_session_get_handle(session);
  const TPM2B_AUTH *auth = tpm2_session_get_auth_value(session);
  TSS2_RC res = Esys_TR_SetAuth(ectx, object, auth);
  if(res != TSS2_RC_SUCCESS){
    printf("Error while setting Auth (tpm2_auth_util_get_shandle)\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  return TSS2_RC_SUCCESS;
}

TSS2_RC start_hmac_session(ESYS_CONTEXT *ectx, TPM2B_AUTH *auth, tpm2_session **session){
  tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_HMAC);
  if(!d){
    printf("Error during tpm2_session_data_new in start_hmac_session\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  TSS2_RC res = tpm2_session_open(ectx, d, session);
  if(res != TSS2_RC_SUCCESS){
    printf("Error while opening session (start_hmac_session)\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  tpm2_session_set_auth_value(*session, auth);

  return TSS2_RC_SUCCESS;
}

TSS2_RC tpm2_util_object_load_auth(ESYS_CONTEXT *ctx, const char *objectstr,const char *auth,
  tpm2_loaded_object *outobject,bool is_restricted_pswd_session, tpm2_handle_flags flags){

  ESYS_CONTEXT *tmp_ctx = is_restricted_pswd_session ? NULL : ctx;
  //do_auth = true;
  tpm2_session *s = NULL;
  // auth = password which in this case is NULL
  const char *password = auth ? auth : "";

  // handle_password_session --> in our case force password to be NULL (no need to handle it!!)
  TPM2B_AUTH auth2 = { 0 };
  /* str may or may not have the str: prefix */
  auth2.size = 0;

  TSS2_RC res = start_hmac_session(ctx, &auth2, &s);
  if(res != TSS2_RC_SUCCESS){
    printf("Error while starting hmac session (tpm2_util_object_load_auth)\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  outobject->session = s;

  if(!objectstr) {
    printf("Object string is empty! Try \"owner\" or ..\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  // Convert a hierarchy ("owner" or ..) or raw handle
  TPMI_RH_PROVISION handle = 0;
  if ((flags & TPM2_HANDLE_FLAGS_NV) && (flags & TPM2_HANDLE_FLAGS_PCR)) {
        printf("Cannot specify NV and PCR index together");
        return TSS2_ESYS_RC_BAD_VALUE;
    }
  bool is_o = !strncmp(objectstr, "owner", strlen(objectstr));
  if (is_o) {
    handle = TPM2_RH_OWNER;
  }
  bool is_e = !strncmp(objectstr, "endorsement", strlen(objectstr));
  if (is_e) {
    handle = TPM2_RH_ENDORSEMENT;
  }

  if(handle != 0){
    outobject->handle = handle;
    outobject->path = NULL;
    if(is_o){
      outobject->tr_handle = ESYS_TR_RH_OWNER;
    }else if(is_e) outobject->tr_handle = ESYS_TR_RH_ENDORSEMENT;

    return TSS2_RC_SUCCESS;
  }

  return TSS2_ESYS_RC_BAD_VALUE;
}

TSS2_RC tpm2_auth_util_from_optarg(ESYS_CONTEXT *ectx, const char *password, tpm2_session **session, bool is_restricted){
  // In our case always NULL
  password = password ? password : "";

  //handle password session
  // handle_password_session --> in our case force password to be NULL (no need to handle it!!)
  TPM2B_AUTH auth2 = { 0 };
  /* str may or may not have the str: prefix */
  auth2.size = 0;

  TSS2_RC res = start_hmac_session(ectx, &auth2, session);
  if(res != TSS2_RC_SUCCESS){
    printf("Error while starting hmac session (tpm2_util_object_load_auth)\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }
}

void tpm2_session_free(tpm2_session **session) {

  tpm2_session *s = *session;

  if(s){
    free(s->input);
    if(s->internal.path){
      free(s->internal.path);
    }
    free(s);
    *session = NULL;
  }
}

TSS2_RC tpm2_flush_context(ESYS_CONTEXT *esys_context, ESYS_TR flush_handle) {

  TSS2_RC res = Esys_FlushContext(esys_context, flush_handle);
  if(res != TSS2_RC_SUCCESS){
    printf("Error while flushing context\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }
  return TSS2_RC_SUCCESS;
}

TSS2_RC tpm2_session_close(tpm2_session **s) {

  if(!*s){
    return TSS2_RC_SUCCESS;
  }

  /*
  * Do not back up:
  *   - password sessions are implicit
  *   - hmac sessions live the life of the tool
  */
    TSS2_RC rc = TSS2_RC_SUCCESS;
    tpm2_session *session = *s;
    if (session->output.session_handle == ESYS_TR_PASSWORD) {
        goto out2;
    }

  const char *path = session->internal.path;
  FILE *session_file = path ? fopen(path, "w+b") : NULL;
  if (path && !session_file) {
    printf("Could not open path \"%s\"", path);
       rc = TSS2_ESYS_RC_BAD_VALUE;
       goto out;
   }

  bool flush = path ? session->internal.is_final : true;
  if (flush) {
      rc = tpm2_flush_context(session->internal.ectx, session->output.session_handle);
      goto out;
  }

out:
 if(session_file) {
   fclose(session_file);
 }

out2:
  tpm2_session_free(s);

  return rc;
}

TSS2_RC tpm2_get_capability(ESYS_CONTEXT *esys_context, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, TPM2_CAP capability, UINT32 property, UINT32 property_count, TPMI_YES_NO *more_data, TPMS_CAPABILITY_DATA **capability_data) {

    TSS2_RC rval = Esys_GetCapability(esys_context, shandle1, shandle2, shandle3,
            capability, property, property_count, more_data, capability_data);
    if (rval != TSS2_RC_SUCCESS) {
        printf("Error while Esys_GetCapability\n");
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return rval;
}

TSS2_RC tpm2_capability_get(ESYS_CONTEXT *ectx, TPM2_CAP capability, UINT32 property, UINT32 count, TPMS_CAPABILITY_DATA **capability_data) {

    TPMI_YES_NO more_data;
    UINT32 property_count = 0;
    *capability_data = NULL;

    do {

        /* fetch capability info */
        TPMS_CAPABILITY_DATA *fetched_data = NULL;
        TSS2_RC rc = tpm2_get_capability(ectx, ESYS_TR_NONE, ESYS_TR_NONE,
                ESYS_TR_NONE, capability, property, count - property_count,
                &more_data, &fetched_data);
        //printf("GetCapability: capability: 0x%x, property: 0x%x\n", capability, property);

        if (rc != TSS2_RC_SUCCESS) {
            if (*capability_data) {
                free(*capability_data);
                *capability_data = NULL;
            }
            return rc;
        }

        if (fetched_data->capability != capability) {
            printf("TPM returned different capability than requested: 0x%x != "
                    "0x%x\n", fetched_data->capability, capability);
            free(fetched_data);
            if (*capability_data) {
                free(*capability_data);
                *capability_data = NULL;
            }
            return TSS2_ESYS_RC_BAD_VALUE;
        }

        if (*capability_data == NULL) {
            /* reuse the TPM's result structure */
            *capability_data = fetched_data;

            if (!more_data) {
                /* there won't be another iteration of the loop, just return the result unmodified */
                return TSS2_RC_SUCCESS;
            }
        }

        /* append the TPM's results to the initial structure, as long as there is still space left */
        switch (capability) {
        case TPM2_CAP_ALGS:
            APPEND_CAPABILITY_INFORMATION(algorithms, algProperties, .alg,
                    TPM2_MAX_CAP_ALGS);
            break;
        case TPM2_CAP_HANDLES:
            APPEND_CAPABILITY_INFORMATION(handles, handle,,
                    TPM2_MAX_CAP_HANDLES);
            break;
        case TPM2_CAP_COMMANDS:
            APPEND_CAPABILITY_INFORMATION(command, commandAttributes,,
                    TPM2_MAX_CAP_CC);
            /* workaround because tpm2-tss does not implement attribute commandIndex for TPMA_CC */
            property &= TPMA_CC_COMMANDINDEX_MASK;
            break;
        case TPM2_CAP_PP_COMMANDS:
            APPEND_CAPABILITY_INFORMATION(ppCommands, commandCodes,,
                    TPM2_MAX_CAP_CC);
            break;
        case TPM2_CAP_AUDIT_COMMANDS:
            APPEND_CAPABILITY_INFORMATION(auditCommands, commandCodes,,
                    TPM2_MAX_CAP_CC);
            break;
        case TPM2_CAP_PCRS:
            APPEND_CAPABILITY_INFORMATION(assignedPCR, pcrSelections, .hash,
                    TPM2_NUM_PCR_BANKS);
            break;
        case TPM2_CAP_TPM_PROPERTIES:
            APPEND_CAPABILITY_INFORMATION(tpmProperties, tpmProperty, .property,
                    TPM2_MAX_TPM_PROPERTIES);
            break;
        case TPM2_CAP_PCR_PROPERTIES:
            APPEND_CAPABILITY_INFORMATION(pcrProperties, pcrProperty, .tag,
                    TPM2_MAX_PCR_PROPERTIES);
            break;
        case TPM2_CAP_ECC_CURVES:
            APPEND_CAPABILITY_INFORMATION(eccCurves, eccCurves,,
                    TPM2_MAX_ECC_CURVES);
            break;
        case TPM2_CAP_VENDOR_PROPERTY:
            APPEND_CAPABILITY_INFORMATION(intelPttProperty, property,,
                    TPM2_MAX_PTT_PROPERTIES);
            break;
        default:
            printf("Unsupported capability: 0x%x\n", capability);
            if (fetched_data != *capability_data) {
                free(fetched_data);
            }
            free(*capability_data);
            *capability_data = NULL;
            return TSS2_ESYS_RC_BAD_VALUE;
        }

        if (fetched_data != *capability_data) {
            free(fetched_data);
        }
    } while (more_data);

    return TSS2_RC_SUCCESS;
}

TSS2_RC tpm2_capability_find_vacant_persistent_handle(ESYS_CONTEXT *ctx, bool is_platform, TPMI_DH_PERSISTENT *vacant) {

  TPMS_CAPABILITY_DATA *capability_data;
  bool handle_found = false;
  TSS2_RC res;

  res = tpm2_capability_get(ctx, TPM2_CAP_HANDLES, TPM2_PERSISTENT_FIRST, TPM2_MAX_CAP_HANDLES, &capability_data);
  if(res != TSS2_RC_SUCCESS){
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  UINT32 count = capability_data->data.handles.count;
  if(count == 0){
    /* There aren't any persistent handles, so use the first */
    *vacant = is_platform ? TPM2_PLATFORM_PERSISTENT : TPM2_PERSISTENT_FIRST;
    handle_found = true;
  } else if (count == TPM2_MAX_CAP_HANDLES){
    /* All persistent handles are already in use */
    goto out;
  }
  else if (count < TPM2_MAX_CAP_HANDLES){
    /*
    * iterate over used handles to ensure we're selecting
    * the next available handle.
    *
    * Platform handles start at a higher hange
    */
    UINT32 i;
    for(i = is_platform ? TPM2_PLATFORM_PERSISTENT : TPM2_PERSISTENT_FIRST; i<= (UINT32) TPM2_PERSISTENT_LAST; i++){
      bool inuse = false;
      UINT32 c;

      for(c=0; c<count; ++c){
        if(capability_data->data.handles.handle[c] == i){
          inuse = true;
          break;
        }
      }

      if(!is_platform && i>= TPM2_PLATFORM_PERSISTENT){
        break;
      }

      if(!inuse){
        *vacant = i;
        handle_found = true;
        break;
      }
    }
  }

out:
  free(capability_data);
  return handle_found ? TSS2_RC_SUCCESS : TSS2_ESYS_RC_BAD_VALUE;

}
