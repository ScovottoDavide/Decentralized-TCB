#if !defined( COMMON_H )
#define COMMON_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <dirent.h>
#include <time.h>
#include <ctype.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_mu.h>

#include "WAM/WAM.h"
#include "../Consensous/consensous.h"

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
  uint8_t ak_digest[SHA256_DIGEST_LENGTH+1];
  uint16_t number_white_entries;
  uint8_t is_quote_successful;
  UNTRUSTED_PATH *untrusted_entries;
} VERIFICATION_RESPONSE;

typedef struct {
    u_int8_t ak_digest[SHA256_DIGEST_LENGTH + 1];
    unsigned char *pcr10_sha1, *pcr10_sha256;
} PCRS_MEM;

typedef struct {
    u_int8_t ak_md[SHA256_DIGEST_LENGTH];
    u_int8_t *path_name;
} AK_FILE_TABLE;

struct whitelist_entry {
    u_int8_t digest[SHA256_DIGEST_LENGTH*2+1];
    u_int16_t path_len;
    char *path;
};
typedef struct{
    u_int8_t ak_digest[SHA256_DIGEST_LENGTH+1];
    u_int16_t number_of_entries;
    struct whitelist_entry *white_entries;
}WHITELIST_TABLE;

/* THREAD DATA STRUCTURES AND PROTOTYPES */
  typedef struct {
  const char *index_file_path_name;
  int nodes_number;
  }ARGS;
  typedef struct {
    pthread_mutex_t *menuLock;
    volatile int *verifier_status;
  }ARGS_MENU;
  int my_gets_avoid_bufferoverflow(char *buffer, size_t buffer_len);
  void menu(void *in);
/* ----------------------------- */

bool legal_int(const char *str);
bool openAKPub(const char *path, unsigned char **akPub);
int computeDigestEVP(unsigned char* akPub, const char* sha_alg, unsigned char *digest);
u_int8_t* get_ak_file_path(AK_FILE_TABLE *ak_table, TO_SEND TpaData, int nodes_number);
int computePCRsoftBinding(unsigned char *pcr_concatenated, const char *sha_alg, unsigned char *digest, int size);
bool get_my_ak_digest(uint8_t *my_ak_digest);
bool PCR9_calculation(unsigned char *expected_PCR9sha1, unsigned char *expected_PCR9sha256, AK_FILE_TABLE *ak_table,
            TO_SEND TpaData, int nodes_number);
void get_Index_from_file(FILE *index_file, IOTA_Index *heartBeat_index, IOTA_Index *write_index, IOTA_Index *read_indexes, 
    IOTA_Index *read_indexes_AkPub, IOTA_Index *read_indexes_whitelist, IOTA_Index *read_indexes_status, int nodes_number);
void parseTPAdata(TO_SEND *TpaData, uint8_t *read_attest_message, int node_number);
void sendLocalTrustStatus(WAM_channel *ch_send, STATUS_TABLE local_trust_status, int nodes_number);
int readOthersTrustTables_Consensus(WAM_channel *ch_read_status, int nodes_number, STATUS_TABLE local_trust_status, int *invalid_channels_status, pthread_mutex_t *menuLock, volatile int verifier_status);

typedef struct IRdata_ctx IRdata_ctx;
struct IRdata_ctx {
  TO_SEND *TpaData; 
  VERIFICATION_RESPONSE *ver_response; 
  AK_FILE_TABLE *ak_table; 
  NONCE_BLOB nonce_blob;
  WHITELIST_TABLE *whitelist_table; 
  PCRS_MEM *pcrs_mem;
  STATUS_TABLE local_trust_status;
  unsigned char *pcr9_sha1; 
  unsigned char *pcr9_sha256;
};

void init_IRdata(IRdata_ctx *ctx, int nodes_number);

#endif