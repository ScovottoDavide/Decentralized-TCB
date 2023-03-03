#if !defined(ALL_UTIL_H)
#define ALL_UTIL_H

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#include <openssl/rsa.h>
#else
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#endif

#include "WAM/WAM.h"
#include "../IMA/ima_read_writeOut_binary.h"

#define HANDLE_SIZE 11

typedef enum tpm2_handle_flags tpm2_handle_flags;
enum tpm2_handle_flags {
    TPM2_HANDLE_FLAGS_NONE = 0,
    TPM2_HANDLE_FLAGS_O = 1 << 0,
    TPM2_HANDLE_FLAGS_P = 1 << 1,
    TPM2_HANDLE_FLAGS_E = 1 << 2,
    TPM2_HANDLE_FLAGS_N = 1 << 3,
    TPM2_HANDLE_FLAGS_L = 1 << 4,
    TPM2_HANDLE_FLAGS_ALL_HIERACHIES = 0x1F,
    TPM2_HANDLES_FLAGS_TRANSIENT = 1 << 5,
    TPM2_HANDLES_FLAGS_PERSISTENT = 1 << 6,
    /* bits 7 and 8 are mutually exclusive */
    TPM2_HANDLE_FLAGS_NV = 1 << 7,
    TPM2_HANDLE_ALL_W_NV = 0xFF,
    TPM2_HANDLE_FLAGS_PCR = 1 << 8,
    TPM2_HANDLE_ALL_W_PCR = 0x17F,
};

typedef struct tpm2_session_data tpm2_session_data;
struct tpm2_session_data {
  ESYS_TR key;
  ESYS_TR bind;
  TPM2_SE session_type;
  TPMT_SYM_DEF symmetric;
  TPMI_ALG_HASH auth_hash;
  TPM2B_NONCE nonce_caller;
  TPMA_SESSION attrs;
  TPM2B_AUTH auth_data;
  const char *path;
};

typedef struct tpm2_session tpm2_session;
struct tpm2_session {
  tpm2_session_data* input;

  struct {
    ESYS_TR session_handle;
  }output;

  struct{
    char *path;
    ESYS_CONTEXT *ectx;
    bool is_final;
  }internal;
};

typedef struct tpm2_hierarchy_pdata tpm2_hierarchy_pdata;
struct tpm2_hierarchy_pdata {

  struct {
        TPMI_RH_PROVISION hierarchy;
        TPM2B_SENSITIVE_CREATE sensitive;
        TPM2B_PUBLIC public;
        TPM2B_DATA outside_info;
        TPML_PCR_SELECTION creation_pcr;
        ESYS_TR object_handle;
    } in;

    struct {
        ESYS_TR handle;
        TPM2B_PUBLIC *public;
        TPM2B_DIGEST *hash;
        struct {
            TPM2B_CREATION_DATA *data;
            TPMT_TK_CREATION *ticket;
        } creation;
    } out;
};

typedef struct tpm2_loaded_object tpm2_loaded_object;
struct tpm2_loaded_object{
  TPM2_HANDLE handle;
  ESYS_TR tr_handle;
  const char *path;
  tpm2_session *session;
};
#endif