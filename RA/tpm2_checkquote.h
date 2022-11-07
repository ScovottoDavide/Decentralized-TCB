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

#include "read_akpub.h"
#include "load_whitelists.h"

#define BUFFER_SIZE(type, field) (sizeof((((type *)NULL)->field)))
#define TPM2B_TYPE_INIT(type, field) { .size = BUFFER_SIZE(type, field), }

#define ARRAY_LEN(x) sizeof(sizeof(x) / sizeof((x)[0]))

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

#define TCG_EVENT_NAME_LEN_MAX	255
struct event {
	struct {
		u_int32_t pcr;
		u_int8_t digest[SHA_DIGEST_LENGTH];
		u_int32_t name_len;
	} header;
	char name[TCG_EVENT_NAME_LEN_MAX + 1];
	u_int32_t template_data_len;
	u_int8_t *template_data;	/* template related data */
};
typedef struct {
  u_int8_t tag; // 4
  u_int16_t size;
  u_int8_t wholeLog;
  struct event *logEntry; // realloc as soon as the number of log entries passes the preallocated size
} IMA_LOG_BLOB;

typedef struct {
  u_int8_t tag; // 3
  u_int16_t size;
  u_int8_t *buffer;
} AK_DIGEST_BLOB;

typedef struct {
  SIG_BLOB sig_blob;
  MESSAGE_BLOB message_blob;
  IMA_LOG_BLOB ima_log_blob;
  AK_DIGEST_BLOB ak_digest_blob;
} TO_SEND;

typedef struct {
  uint16_t name_len;
  char *untrusted_path_name;
} UNTRUSTED_PATH;
typedef struct {
  uint8_t tag; // 5
  uint16_t number_white_entries;
  UNTRUSTED_PATH *untrusted_entries;
} VERIFICATION_RESPONSE;

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

u_int8_t* get_ak_file_path(AK_FILE_TABLE *ak_table, TO_SEND TpaData, int nodes_number);
TSS2_RC get_internal_attested_data(TPM2B_ATTEST *quoted, TPMS_ATTEST *attest);
bool tpm2_openssl_hash_compute_data(TPMI_ALG_HASH halg, BYTE *buffer, UINT16 length, TPM2B_DIGEST *digest);
bool calculate_pcr_digest(unsigned char *pcr10_sha256, unsigned char *pcr10_sha1, unsigned char *pcr9_sha256, unsigned char *pcr9_sha1,
                            TPMI_ALG_HASH hash_alg, TPM2B_DIGEST *digest);

bool tpm2_public_load_pkey(const char *path, EVP_PKEY **pkey);
bool tpm2_util_verify_digests(TPM2B_DIGEST *quoteDigest, TPM2B_DIGEST *pcr_digest);
bool verify(void);

bool tpm2_checkquote(TO_SEND TpaData, NONCE_BLOB nonce_blob, AK_FILE_TABLE *ak_table, int nodes_number, unsigned char *pcr10_sha256, unsigned char *pcr10_sha1,
                    unsigned char *pcr9_sha256, unsigned char *pcr9_sha1);