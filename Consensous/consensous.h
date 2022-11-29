#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>

typedef struct {
  uint8_t ak_digest[SHA256_DIGEST_LENGTH+1];
  uint8_t status; // 0 = NT, 1 = T, 2 = NT and already ignored
}STATUS_ENTRY;

typedef struct {
  uint16_t number_of_entries;
  STATUS_ENTRY *status_entries;
}STATUS_TABLE;

void hex_print(uint8_t *raw_data, size_t raw_size);
int get_index_from_digest(STATUS_TABLE *status_table, uint8_t digest[SHA256_DIGEST_LENGTH+1]);
int consensous_proc(STATUS_TABLE *my_local_trust_status, STATUS_TABLE *others_local_trust_status, STATUS_TABLE *global_trust_status, int nodes_number);