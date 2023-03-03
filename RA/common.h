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

typedef struct {
  u_int8_t tag; // 0
  u_int16_t size;
  u_int8_t buffer[32];
} NONCE_BLOB;

typedef struct {
  u_int8_t tag; //1
  u_int16_t size;
  u_int8_t *buffer;
} SIG_BLOB;

typedef struct {
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

/* LOCAL REMOTE ATTESTOR DATA STRUCTURES AND PROTOTYPES */
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
  FILE **ak_files;
};

void init_IRdata_ctx(IRdata_ctx *ctx, int nodes_number);
void freeEarly_IRdata_ctx(IRdata_ctx *ctx, int nodes_number);
void freeLate_IRdata_ctx(IRdata_ctx *ctx, int nodes_number);

typedef struct WAM_ctx WAM_ctx;
struct WAM_ctx {
  IOTA_Index heartBeat_index, *read_indexes, *read_indexes_AK_Whitelist, write_response_index, *read_indexes_status;
  WAM_channel ch_read_hearbeat, *ch_read_attest, ch_write_response, *ch_read_AK_Whitelist, *ch_read_status;
  FILE *index_file;
};
void WAM_ctx_alloc(WAM_ctx *ctx, int nodes_number, const char *file_index_path_name);
void WAM_ctx_init_channels(WAM_ctx *ctx, int nodes_number, IOTA_Endpoint *privatenet, WAM_Key *k, WAM_AuthCtx *a);
void free_WAM_ctx(WAM_ctx *ctx);

typedef struct support_ctx support_ctx;
struct support_ctx {
  int *verified_nodes, *attest_messages_sizes, attest_messages_size_increment, *invalid_channels_attest, *invalid_channels_status;
  uint32_t expected_size, expected_size_attest_message, *offset, fixed_nonce_size;
	uint8_t **read_attest_message, expected_attest_message[DATA_SIZE], nonce[32], last[4];
  uint16_t *previous_msg_num;
};

void init_Support_ctx(support_ctx *ctx, int nodes_number);
void freeEarly_support_ctx(support_ctx *ctx);
void freeLate_support_ctx(support_ctx *ctx, int nodes_number);
/* ---------------------------------------------------- */

bool legal_int(const char *str);
bool openAKPub(const char *path, unsigned char **akPub);
int computeDigestEVP(unsigned char* akPub, const char* sha_alg, unsigned char *digest);
u_int8_t* get_ak_file_path(AK_FILE_TABLE *ak_table, TO_SEND TpaData, int nodes_number);
int computePCRsoftBinding(unsigned char *pcr_concatenated, const char *sha_alg, unsigned char *digest, int size);
bool get_my_ak_digest(uint8_t *my_ak_digest);
bool PCR9_calculation(unsigned char *expected_PCR9sha1, unsigned char *expected_PCR9sha256, AK_FILE_TABLE *ak_table,
            TO_SEND TpaData, int nodes_number);
void get_Index_from_file(WAM_ctx *ctx, int nodes_number);
void parseTPAdata(TO_SEND *TpaData, uint8_t *read_attest_message, int node_number);
void sendLocalTrustStatus(WAM_channel *ch_send, STATUS_TABLE local_trust_status, int nodes_number);
int readOthersTrustTables_Consensus(WAM_channel *ch_read_status, int nodes_number, STATUS_TABLE local_trust_status, int *invalid_channels_status, pthread_mutex_t *menuLock, volatile int verifier_status);
#endif