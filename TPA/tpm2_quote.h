#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_mu.h>
#include "../IMA/ima_read_writeOut_binary.h"

#define ARRAY_LEN(x) sizeof(sizeof(x) / sizeof((x)[0]))

#define BUFFER_SIZE(type, field) (sizeof((((type *)NULL)->field)))
#define TPM2B_TYPE_INIT(type, field)  \
  {                                   \
    .size = BUFFER_SIZE(type, field), \
  }

#define TPM2B_INIT(xsize) \
  {                       \
    .size = xsize,        \
  }
#define TPM2B_EMPTY_INIT TPM2B_INIT(0)

#define MAX_RSA_KEY_BYTES ((2048 + 7) / 8)

typedef struct tpm2_algorithm tpm2_algorithm;
struct tpm2_algorithm
{
  int count;
  TPMI_ALG_HASH alg[TPM2_NUM_PCR_BANKS];
};

typedef struct tpm2_pcrs tpm2_pcrs;
struct tpm2_pcrs
{
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
  u_int8_t tag; // 1
  u_int16_t size;
  u_int8_t buffer[MAX_RSA_KEY_BYTES];
} SIG_BLOB;

typedef struct
{
  u_int8_t tag; // 2
  u_int16_t size;
  u_int8_t buffer[sizeof(TPMS_ATTEST)];
} MESSAGE_BLOB;

typedef struct
{
  NONCE_BLOB nonce_blob;
  SIG_BLOB sig_blob;
  MESSAGE_BLOB message_blob;
  IMA_LOG_BLOB ima_log_blob; // defined in /IMA/ima_read_writeOut_binary.h
} TO_SEND;

bool pcr_parse_list(const char *str, size_t len, TPMS_PCR_SELECTION *pcr_select);
bool pcr_parse_selections(const char *arg, TPML_PCR_SELECTION *pcr_select);

bool files_get_file_size(FILE *fp, unsigned long *file_size, const char *path);
bool read_nonce_from_file(const char *input, UINT16 *len, BYTE *buffer);

TSS2_RC pcr_get_banks(ESYS_CONTEXT *esys_context, TPMS_CAPABILITY_DATA *capability_data, tpm2_algorithm *algs);
TSS2_RC tpm2_public_to_scheme(ESYS_CONTEXT *ectx, ESYS_TR key, TPMI_ALG_PUBLIC *type, TPMT_SIG_SCHEME *sigscheme);
// tpm2_alg_util_get_signature_scheme
TSS2_RC tpm2_get_signature_scheme(ESYS_CONTEXT *ectx, ESYS_TR key_handle, TPMI_ALG_HASH *halg, TPMI_ALG_SIG_SCHEME sig_scheme, TPMT_SIG_SCHEME *scheme);

static void shrink_pcr_selection(TPML_PCR_SELECTION *s);
bool pcr_check_pcr_selection(TPMS_CAPABILITY_DATA *cap_data, TPML_PCR_SELECTION *pcr_sel);
bool pcr_unset_pcr_sections(TPML_PCR_SELECTION *s);
void pcr_update_pcr_selections(TPML_PCR_SELECTION *s1, TPML_PCR_SELECTION *s2);
TSS2_RC pcr_read_pcr_values(ESYS_CONTEXT *esys_context, TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs);
bool pcr_print(TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs);

bool tpm2_openssl_hash_pcr_banks(TPMI_ALG_HASH hash_alg, TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs, TPM2B_DIGEST *digest);
bool tpm2_util_verify_digests(TPM2B_DIGEST *quoteDigest, TPM2B_DIGEST *pcr_digest);

bool tpm2_convert_sig_save(TPMT_SIGNATURE *signature, TO_SEND *TpaData);
bool tpm2_save_message_out(UINT8 *buf, UINT16 size, TO_SEND *TpaData);
static TSS2_RC write_output_files(TO_SEND *TpaData);

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

// tpm2_quote_internal in createak_util.h --> to fix dependencies!!!!!!!!!

TSS2_RC tpm2_quote(ESYS_CONTEXT *esys_ctx, TO_SEND *TpaData, ssize_t imaLogBytesSize);
