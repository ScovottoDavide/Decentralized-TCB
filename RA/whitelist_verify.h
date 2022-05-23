#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define TCG_EVENT_NAME_LEN_MAX	255
#define DIGEST_LEN 64

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
    u_int8_t digest[DIGEST_LEN+1];
    char *path;
};


int computePCR10Aggr(unsigned char *pcr_concatenated, const char *sha_alg, unsigned char **digest, int size);
int match_IMApath_Whitepath(const char *imaPath, const u_int32_t imaPath_len, const struct whitelist_entry *white_entries, int white_entries_size);
static int read_template_data(struct event *template, FILE *fp, const struct whitelist_entry *white_entries, int white_entries_size, u_int8_t pcr_aggr[SHA256_DIGEST_LENGTH]);
int verify_PCR10_whitelist(u_int8_t *pcr10_sha1, u_int8_t *pcr10_sha256);
