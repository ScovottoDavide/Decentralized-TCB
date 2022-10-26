#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>
#include <openssl/rand.h>
#include <dirent.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "/home/pi/WAM/WAM.h"

#define FILENAME_LEN 10
#define FILE_PEM_LEN 8 // .pub.pem

typedef struct {
    u_int8_t ak_md[SHA256_DIGEST_LENGTH];
    u_int8_t *path_name;
} AK_FILE_TABLE;

void cleanUpFolder(char *path);
char* rand_str(size_t length);
int computeDigestEVP(unsigned char* akPub, const char* sha_alg, unsigned char *digest);
bool read_and_save_AKs(WAM_channel *ch_read_ak, AK_FILE_TABLE *ak_table, FILE *ak_file, int node_number);