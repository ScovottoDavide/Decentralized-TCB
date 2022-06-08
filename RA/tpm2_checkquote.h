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

#define ARRAY_LEN(x) sizeof(sizeof(x) / sizeof((x)[0]))

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

typedef struct tpm2_pcrs tpm2_pcrs;
struct tpm2_pcrs {
    size_t count;
    TPML_DIGEST pcr_values[TPM2_MAX_PCRS];
};

typedef struct
{
  u_int8_t tag; // 0
  u_int16_t size;
  u_int8_t buffer[32];
} NONCE_BLOB;

typedef struct
{
  u_int8_t tag; //1
  u_int16_t size;
  u_int8_t *buffer;
} SIG_BLOB;

typedef struct
{
  u_int8_t tag; //2
  u_int16_t size;
  u_int8_t *buffer; // Allocate on the fly
} MESSAGE_BLOB;

typedef struct
{
  u_int8_t tag; // 3
  TPML_PCR_SELECTION pcr_selection;
  tpm2_pcrs pcrs;
} PCRS_BLOB;

typedef struct
{
  NONCE_BLOB nonce_blob;
  SIG_BLOB sig_blob;
  MESSAGE_BLOB message_blob;
  PCRS_BLOB pcrs_blob;
} TO_SEND;


bool files_get_file_size(FILE *fp, unsigned long *file_size, const char *path);
bool read_nonce_from_file(const char *input, UINT16 *len, BYTE *buffer);

TPM2B_ATTEST *message_from_file(const char *msg_file_path);
bool tpm2_load_signature_from_path(const char *path, TPM2B_MAX_BUFFER *signature);

bool parse_selection_data_from_file(FILE *pcr_input, TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs);
bool pcrs_from_file(const char *pcr_file_path, TPML_PCR_SELECTION *pcr_select ,tpm2_pcrs *pcrs);

bool tpm2_openssl_hash_pcr_banks(TPMI_ALG_HASH hash_alg, TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs, TPM2B_DIGEST *digest);
bool pcr_print(TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs);


// It's a "cast" from TPM2B_ATTEST to TPMS_ATTEST to get all the information related to the attested data 
/*
// Table 115 - TPMU_ATTEST Union
 typedef union {
   TPMS_CERTIFY_INFO       certify;
   TPMS_CREATION_INFO      creation;
   TPMS_QUOTE_INFO         quote;
   TPMS_COMMAND_AUDIT_INFO commandAudit;
   TPMS_SESSION_AUDIT_INFO sessionAudit;
   TPMS_TIME_ATTEST_INFO   time;
   TPMS_NV_CERTIFY_INFO    nv;
 } TPMU_ATTEST;
 
 // Table 116 - TPMS_ATTEST Structure
 typedef struct {
   TPM_GENERATED   magic;
   TPMI_ST_ATTEST  type;
   TPM2B_NAME      qualifiedSigner;
   TPM2B_DATA      extraData;
   TPMS_CLOCK_INFO clockInfo;
   UINT64          firmwareVersion;
   TPMU_ATTEST     attested;
 } TPMS_ATTEST;
 
 // Table 117 - TPM2B_ATTEST Structure
 typedef struct {
   UINT16 size;
   BYTE   attestationData[sizeof(TPMS_ATTEST)];
 } TPM2B_ATTEST;
*/
TSS2_RC get_internal_attested_data(TPM2B_ATTEST *quoted, TPMS_ATTEST *attest);
bool tpm2_openssl_hash_compute_data(TPMI_ALG_HASH halg, BYTE *buffer, UINT16 length, TPM2B_DIGEST *digest);


bool tpm2_public_load_pkey(const char *path, EVP_PKEY **pkey);
bool tpm2_util_verify_digests(TPM2B_DIGEST *quoteDigest, TPM2B_DIGEST *pcr_digest);
bool verify(void);

bool tpm2_checkquote(TO_SEND TpaData);