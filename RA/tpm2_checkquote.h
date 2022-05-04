#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_mu.h>


#define BUFFER_SIZE(type, field) (sizeof((((type *)NULL)->field)))
#define TPM2B_TYPE_INIT(type, field) { .size = BUFFER_SIZE(type, field), }


typedef struct {
    UINT16 size;
    BYTE buffer[];
} TPM2B;

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

typedef struct tpm2_loaded_object tpm2_loaded_object;
struct tpm2_loaded_object{
  TPM2_HANDLE handle;
  ESYS_TR tr_handle;
  const char *path;
  tpm2_session *session;
};

bool files_get_file_size(FILE *fp, unsigned long *file_size, const char *path);
bool read_nonce_from_file(const char *input, UINT16 *len, BYTE *buffer);
TPM2B *message_from_file(const char *msg_file_path);
bool tpm2_load_signature_from_path(const char *path, TPM2B_MAX_BUFFER *signature);
TSS2_RC tpm2_checkquote();