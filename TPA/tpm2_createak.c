#include "tpm2_createak.h"

#define AK_TYPE "rsa2048"
#define AK_DIGEST "sha256"
#define AK_SIGN "rsassa"

#define ATTRS  \
    TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_USERWITHAUTH| \
    TPMA_OBJECT_SIGN_ENCRYPT|TPMA_OBJECT_FIXEDTPM| \
    TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN

static createak_context ctx = {
    .ak = {
        .in = {
            .alg = {
                .type = "rsa2048",
                .digest = "sha256",
                .sign = "null"
            },
        },
        .out = {
          .pub_file = "/etc/tc/ak.pub.pem",
        },
    },
    .flags = { 0 },
};

static TSS2_RC init_ak_public(const char* alg_details, TPM2B_PUBLIC *public){
    memset(public, 0, sizeof(*public));

    if(strcmp(alg_details, "rsa2048:sha256:rsassa"))
      return TSS2_ESYS_RC_BAD_VALUE;

    public->size = 0;
    public->publicArea.type = TPM2_ALG_RSA;
    public->publicArea.nameAlg = TPM2_ALG_SHA256;
    public->publicArea.objectAttributes = ATTRS;
    public->publicArea.authPolicy.size = 0;
    public->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
    public->publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 0;
    public->publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    public->publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_RSASSA;
    public->publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;
    public->publicArea.parameters.rsaDetail.keyBits = 2048;
    public->publicArea.parameters.rsaDetail.exponent = 0;
    public->publicArea.unique.rsa.size = 256;
    memset(public->publicArea.unique.rsa.buffer, 0, sizeof(public->publicArea.unique.rsa.buffer));;

    return TSS2_RC_SUCCESS;
}

static TSS2_RC create_ak(ESYS_CONTEXT *ectx, uint16_t *ak_handle) {
  TSS2_RC res;

  TPML_PCR_SELECTION creation_pcr = { .count = 0 };
  TPM2B_DATA outside_info = {.size = 0};
  TPM2B_PUBLIC *out_public;
  TPM2B_PRIVATE *out_private;

  TPM2B_PUBLIC in_public;

  // 0 because EK supports only RSA with policy a_sha_256
  TPML_DIGEST pHashList = { .count = 0 };

  // get the nameHalg of the EK
  // should be sha256 (TPM2_ALG_SHA256)
  TPM2_ALG_ID ek_name_alg = TPM2_ALG_SHA256;

  res = init_ak_public("rsa2048:sha256:rsassa", &in_public);

  tpm2_session_data *data = tpm2_session_data_new(TPM2_SE_POLICY);
  if(!data) {
    printf("Error while allocating session data in createak\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  tpm2_session_set_authhash(data, ek_name_alg);

  tpm2_session *session = NULL;
  res = tpm2_session_open(ectx, data, &session);
  if(res != TSS2_RC_SUCCESS){
    printf("Error while opening session (create_ak)\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  //printf("tpm_session_start_auth_with_params succ\n");

  ESYS_TR sess_handle = tpm2_session_get_handle(session);

  ESYS_TR shandle = ESYS_TR_NONE;

  res = tpm2_auth_util_get_shandle(ectx, ESYS_TR_RH_ENDORSEMENT, ctx.ek.session, &shandle);
  if(res != TSS2_RC_SUCCESS){
    printf("(create_ak) Error while getting EK session handle\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  res = Esys_PolicySecret(ectx, ESYS_TR_RH_ENDORSEMENT, sess_handle, shandle, ESYS_TR_NONE, ESYS_TR_NONE, NULL, NULL, NULL, 0, NULL, NULL);
  if(res != TSS2_RC_SUCCESS){
    printf("(create_ak) Error in Esys_PolicySecret\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  TPM2B_CREATION_DATA *creation_data = NULL;
  res = Esys_Create(ectx, ctx.ek.ek_ctx.tr_handle, sess_handle, ESYS_TR_NONE, ESYS_TR_NONE, &ctx.ak.in.in_sensitive, &in_public, &outside_info, &creation_pcr, &out_private, &out_public, &creation_data, NULL, NULL);
  if(res != TSS2_RC_SUCCESS){
    printf("Errpr while Esys_Create for AK\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  res = tpm2_session_close(&session);
  if(res != TSS2_RC_SUCCESS){
    printf("(create_ak) Error while closing session\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  data = tpm2_session_data_new(TPM2_SE_POLICY);
  if(!data){
    printf("Error while allocating session data OOM \n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }
  tpm2_session_set_authhash(data, ek_name_alg);

  res = tpm2_session_open(ectx, data, &session);
  if(res != TSS2_RC_SUCCESS){
    printf("Error in opening new session\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  sess_handle = tpm2_session_get_handle(session);

  res = tpm2_auth_util_get_shandle(ectx, sess_handle, ctx.ek.session, &shandle);
  if(res != TSS2_RC_SUCCESS){
    printf("Cannot get session handle EK\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  res = Esys_PolicySecret(ectx, ESYS_TR_RH_ENDORSEMENT, sess_handle, shandle, ESYS_TR_NONE, ESYS_TR_NONE, NULL, NULL, NULL, 0, NULL, NULL);
  if(res != TSS2_RC_SUCCESS){
    printf("(create_ak) Error in Esys_PolicySecret\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  ESYS_TR loaded_sha1_key_handle;
  res = Esys_Load(ectx, ctx.ek.ek_ctx.tr_handle, sess_handle, ESYS_TR_NONE, ESYS_TR_NONE, out_private, out_public, &loaded_sha1_key_handle);
  if(res != TSS2_RC_SUCCESS){
    printf("Error while loading AK priv and AK pub \n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  // Load the TPM2 handle so that we can print it
  TPM2B_NAME *key_name;
  res = Esys_TR_GetName(ectx, loaded_sha1_key_handle, &key_name);
  if(res != TSS2_RC_SUCCESS){
    printf("Error while getting GetName\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  res = tpm2_session_close(&session);
  if(res != TSS2_RC_SUCCESS){
    printf("Error while closing session \n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  // print name
  /*fprintf(stdout, "loaded-key:\n   name:");
  int i=0;
  for(i=0; i<key_name->size; i++){
    fprintf(stdout, "%x", key_name->name[i]);
  }
  fprintf(stdout, "\n");*/

  // If the AK isn't persisted we always save a context file of the
  // transient AK handle for future tool interactions.

  // I persist it so no need to save out the context
  res = tpm2_capability_find_vacant_persistent_handle(ectx, false, &ctx.ak.object.handle);
  if(res != TSS2_RC_SUCCESS){
    printf("Error while trying to find vacant persistent handle\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  } else {
    //fprintf(stdout, "Found persistent handle at 0x%x\n", ctx.ak.object.handle);
    snprintf((char *)ak_handle, HANDLE_SIZE, "0x%X", ctx.ak.object.handle);
  }

  ESYS_TR out_handle = ESYS_TR_NONE;

  res = Esys_EvictControl(ectx, ESYS_TR_RH_OWNER, loaded_sha1_key_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, ctx.ak.object.handle, &out_handle);
  if(res != TSS2_RC_SUCCESS){
    printf("Error while making AK handle persistent\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  if (ctx.ak.out.pub_file) {
     bool ok = tpm2_convert_pubkey_save(out_public, ctx.ak.out.pub_file);
     if (!ok) {
         return TSS2_ESYS_RC_BAD_VALUE;
     }
 }
  return TSS2_RC_SUCCESS;
}

TSS2_RC tpm2_tool_onrun(ESYS_CONTEXT *ectx, uint16_t *ek_handle, uint16_t *ak_handle) {
  TSS2_RC res;

  // TODO
  /*if (ctx.flags.f && !ctx.ak.out.pub_file) {
    printf("Please specify an output file name when specifying a format\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }*/

  // I persist it, no need to save the context
  /*if (!ctx.ak.out.ctx_file) {
    printf("Expected option -c\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }*/

  // This is the -C option in createak command
  ctx.ek.ctx_arg = malloc(HANDLE_SIZE * sizeof(char));
  snprintf((char *)ctx.ek.ctx_arg, HANDLE_SIZE, "%s", ek_handle);
  res = tpm2_util_object_load(ectx, ctx.ek.ctx_arg, &ctx.ek.ek_ctx, TPM2_HANDLE_ALL_W_NV);
  if(res != TSS2_RC_SUCCESS){
    printf("Could not load EK context\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  if(!ctx.ek.ek_ctx.tr_handle){
    res = tpm2_util_sys_handle_to_esys_handle(ectx, ctx.ek.ek_ctx.handle, &ctx.ek.ek_ctx.tr_handle);
    if(res != TSS2_RC_SUCCESS){
      printf("(tpm2_tool_onrun) Error converting ek_ctx TPM2_HANDLE to ESYS_TR\n");
      return TSS2_ESYS_RC_BAD_VALUE;
    }
  }

  res = tpm2_auth_util_from_optarg(NULL, ctx.ek.auth_str, &ctx.ek.session, true);
  if(res != TSS2_RC_SUCCESS){
    printf("(tpm2_tool_onrun) Invalid endorse authorization\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  tpm2_session *tmp;
  res = tpm2_auth_util_from_optarg(NULL, ctx.ak.auth_str, &tmp, true);
  if(res != TSS2_RC_SUCCESS){
    printf("(tpm2_tool_onrun) Invalid AK authorization\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  const TPM2B_AUTH *auth = tpm2_session_get_auth_value(tmp);
  ctx.ak.in.in_sensitive.sensitive.userAuth = *auth;

  res = tpm2_session_close(&tmp);
  if(res != TSS2_RC_SUCCESS){
    printf("(tpm2_tool_onrun) Error while closing session\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  return create_ak(ectx, ak_handle);
}

TSS2_RC tpm2_createak(ESYS_CONTEXT *ectx, uint16_t *ek_handle, uint16_t *ak_handle) {
  return tpm2_tool_onrun(ectx, ek_handle, ak_handle);
}
