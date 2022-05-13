#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define TCG_EVENT_NAME_LEN_MAX	255
#define DIGEST_LEN 32

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

struct whitelist_entry {
    u_int8_t digest[DIGEST_LEN];
    char *path;
};

int verify();