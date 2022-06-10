#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

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

struct event_blob {
	struct {
		u_int32_t pcr;
		u_int8_t digest[SHA_DIGEST_LENGTH];
		u_int32_t name_len;
	} header;
	char name[TCG_EVENT_NAME_LEN_MAX + 1];
	u_int32_t template_data_len;
	u_int8_t template_data[512];	/* template related data */
};

typedef struct {
  u_int8_t tag; // 4
  u_int16_t size;
  struct event_blob *logEntry; // realloc as soon as the number of log entries passes the preallocated size
} IMA_LOG_BLOB;

static int read_template_data(struct event *template, FILE *fp, struct event_blob *blob_template);
int read_write_IMAb(const char *path, IMA_LOG_BLOB *ima_log_blob);
