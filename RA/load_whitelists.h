#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "/home/pi/WAM/WAM.h"

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

int getIndexFromDigest(u_int8_t *ak_digest, WHITELIST_TABLE *whitelist_table, int nodes_number);
void read_and_save_whitelist(WAM_channel *ch_read_whitelist, WHITELIST_TABLE *whitelist_table, int node_number);