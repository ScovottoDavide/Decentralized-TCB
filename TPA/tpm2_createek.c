#include "tpm2_createek.h"
#include "createek_util.h"

#define DEFAULT_KEY_ALG "rsa"

#define ATTRS_A \
    TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT| \
    TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_ADMINWITHPOLICY| \
    TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT

static const TPM2B_DIGEST policy_a_sha256 = {
    .size = 32,
    .buffer = {
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90,
        0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E,
        0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
        0x69, 0xAA
    }
};

typedef struct createek_context createek_context;
struct createek_context{

  struct {
    const char *ctx_path;
    const char *auth_str;
    tpm2_loaded_object object;
  } auth_owner_hierarchy;

  struct {
    const char *ctx_path;
    const char *auth_str;
    tpm2_loaded_object object;
  } auth_endorse_hierarchy;

  struct {
    const char *ctx_path;
    const char *auth_str;
    tpm2_loaded_object object;
  } auth_ek;

  const char *key_alg;
  tpm2_hierarchy_pdata objdata;
  char *out_file_path;

  struct {
    UINT8 f :1;
    UINT8 t :1;
  } flags;

  bool find_persistent_handle;
};

/* initialize the EK context */
static  createek_context ctx = {
  .key_alg = DEFAULT_KEY_ALG,
  .objdata = {
    .in = {
      .sensitive = TPM2B_SENSITIVE_CREATE_EMPTY_INIT,
      .hierarchy = TPM2_RH_ENDORSEMENT
    },
  },
  .out_file_path = "/etc/tc/ek.pub.pem",
  .flags = { 0 },
  .find_persistent_handle = false
};

typedef struct alg_map alg_map;
struct alg_map {
  const char *input;
  const char *alg;
  const char *namealg;
  const TPM2B_DIGEST *policy;
  const TPMA_OBJECT attrs;
};

/* For now only 1 alg map supported */
static const alg_map alg_maps[] = {
  {"rsa", "rsa2048:aes128cfb", "sha256", &policy_a_sha256, ATTRS_A},
};

/* algmap[0] is RSA --> only this supported */
static TSS2_RC init_ek_public(TPM2B_PUBLIC *public){
  const alg_map m = alg_maps[0]; // RSA

  TSS2_RC res = tpm2_public_init(m.alg, m.namealg, m.attrs, public);

  if(res != TSS2_RC_SUCCESS){
    printf("Could not initialize ek public!\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  /* Set the policy */
  public->publicArea.authPolicy = *m.policy;

  if(public->publicArea.type == TPM2_ALG_RSA && public->publicArea.parameters.rsaDetail.keyBits == 2048 ){
    public->publicArea.unique.rsa.size = 256;
    memset(public->publicArea.unique.rsa.buffer, 0, sizeof(public->publicArea.unique.rsa.buffer));
  }

  return TSS2_RC_SUCCESS;
}

TSS2_RC tpm2_createek(ESYS_CONTEXT *ectx, uint16_t *ek_handle) {
  TSS2_RC res;
  ESYS_TR objectHandle = ESYS_TR_NONE;
  TPM2B_PUBLIC inPublic;
  TPM2B_PUBLIC *outPublic = NULL;

  tpm2_session **sessions[] = {
#if 0
   &ctx.auth.ek.session,
   &ctx.auth.endorse.session,
   &ctx.auth.owner.session,
#endif
   &ctx.auth_owner_hierarchy.object.session,
   &ctx.auth_endorse_hierarchy.object.session,
   &ctx.auth_ek.object.session,
};

res = tpm2_util_object_load_auth(ectx, "owner", NULL, &ctx.auth_owner_hierarchy.object, false, TPM2_HANDLE_FLAGS_O);
if(res != TSS2_RC_SUCCESS){
  printf("Invalid owner hierarchy authorization\n");
  return TSS2_ESYS_RC_BAD_VALUE;
}

res = tpm2_util_object_load_auth(ectx, "endorsement", NULL, &ctx.auth_owner_hierarchy.object, false, TPM2_HANDLE_FLAGS_E);
if(res != TSS2_RC_SUCCESS){
  printf("Invalid endorsement hierarchy authorization\n");
  return TSS2_ESYS_RC_BAD_VALUE;
}

res = tpm2_auth_util_from_optarg(ectx, ctx.auth_ek.auth_str, &ctx.auth_ek.object.session, false);
if(res != TSS2_RC_SUCCESS){
  printf("Invalid EK authorization\n");
  return TSS2_ESYS_RC_BAD_VALUE;
}

  TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = {
                 .size = 0,
                 .buffer = {0}
                 ,
             },
            .data = {
                 .size = 0,
                 .buffer = {0}
             }
        }
    };

  init_ek_public(&inPublic);

  TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {}
        ,
    };
    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };
    TPM2B_AUTH authValue = {
        .size = 0,
        .buffer = {}
    };

    res = Esys_CreatePrimary(ectx, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                             &inSensitive, &inPublic, &outsideInfo, &creationPCR, &objectHandle,
                              &outPublic, NULL, NULL, NULL);
    if(res != TSS2_RC_SUCCESS){
      printf("Error while creating EK\n");
      return TSS2_ESYS_RC_BAD_VALUE;
    }

    // I persist it so no need to save out the context
    res = tpm2_capability_find_vacant_persistent_handle(ectx, false, &ctx.auth_ek.object.handle);
    if(res != TSS2_RC_SUCCESS){
      printf("Error while trying to find vacant persistent handle\n");
      return TSS2_ESYS_RC_BAD_VALUE;
    } else {
      //fprintf(stdout, "Found free persistent handle at 0x%x\n", ctx.auth_ek.object.handle);
      snprintf((char *)ek_handle, HANDLE_SIZE, "0x%X", ctx.auth_ek.object.handle);
    }

    ESYS_TR out_handle;
    res = Esys_EvictControl(ectx, ESYS_TR_RH_OWNER, objectHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, ctx.auth_ek.object.handle, &out_handle);
    if(res != TSS2_RC_SUCCESS){
      printf("Error while making EK handle persistent\n");
      return TSS2_ESYS_RC_BAD_VALUE;
    }

    if (ctx.out_file_path) {
       bool ok = tpm2_convert_pubkey_save(outPublic, ctx.out_file_path);
       if (!ok) {
           return TSS2_ESYS_RC_BAD_VALUE;
       }
   }
   res = Esys_FlushContext(ectx, objectHandle);
    if (res != TSS2_RC_SUCCESS) {
        return res;
    }
  return TSS2_RC_SUCCESS;
}
