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
	struct ima_template_desc *template_desc; /* template descriptor */
	u_int32_t template_data_len;
	u_int8_t *template_data;	/* template related data */
};

static int display_digest(u_int8_t * digest, u_int32_t digestlen, FILE *fout);
static int read_template_data(struct event *template, FILE *fp, FILE *fout);
int read_write_IMAb(const char *path);
