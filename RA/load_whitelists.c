#include "load_whitelists.h"

int getIndexFromDigest(u_int8_t *ak_digest, WHITELIST_TABLE *whitelist_table, int nodes_number) {
    int i; 
    unsigned char string_digest[SHA256_DIGEST_LENGTH*2 + 1];
    
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&string_digest[i * 2], "%02x", ak_digest[i]);
    }
    string_digest[SHA256_DIGEST_LENGTH*2] = '\0';
    for(i = 0; i < nodes_number; i++){
        if(strcmp(string_digest, whitelist_table[nodes_number].ak_digest) == 0)
            return i;
    }
    return -1;
}

void read_and_save_whitelist(WAM_channel *ch_read_whitelist, WHITELIST_TABLE *whitelist_table, int node_number) {
    unsigned char expected_message[DATA_SIZE];
    uint32_t expected_size = DATA_SIZE, offset = 0;
    uint8_t *read_whitelist_message = (uint8_t *) malloc(sizeof(uint8_t) * DATA_SIZE * 3), last[4] = "done";
    int acc = 0, i;

    do{
        WAM_read(ch_read_whitelist, expected_message, &expected_size);
        if(ch_read_whitelist->recv_bytes <= 0){
            fprintf(stdout, "Whitelist not uploaded!\n");
            return ;
        }
        memcpy(read_whitelist_message + offset, expected_message, DATA_SIZE);
        offset += DATA_SIZE;
    }while(memcmp(last, read_whitelist_message + ch_read_whitelist->recv_bytes - sizeof last, sizeof last) != 0);

    memcpy(whitelist_table[node_number].ak_digest, read_whitelist_message + acc, sizeof(u_int8_t) * SHA256_DIGEST_LENGTH);
    whitelist_table[node_number].ak_digest[SHA256_DIGEST_LENGTH] = '\0';
    acc += sizeof(u_int8_t) * SHA256_DIGEST_LENGTH;
    memcpy(&whitelist_table[node_number].number_of_entries, read_whitelist_message + acc, sizeof(u_int16_t));
    acc += sizeof(u_int16_t);   
    whitelist_table[node_number].white_entries = malloc(whitelist_table[node_number].number_of_entries * sizeof(struct whitelist_entry));
    for(i = 0; i < whitelist_table[node_number].number_of_entries; i++) {
        memcpy(&whitelist_table[node_number].white_entries[i].digest, read_whitelist_message + acc, sizeof(u_int8_t) * SHA256_DIGEST_LENGTH * 2);
        acc += sizeof(u_int8_t) * SHA256_DIGEST_LENGTH * 2;
        memcpy(&whitelist_table[node_number].white_entries[i].path_len, read_whitelist_message + acc, sizeof(u_int16_t));
        acc += sizeof(u_int16_t);
        whitelist_table[node_number].white_entries[i].path = malloc(sizeof(u_int8_t) * whitelist_table[node_number].white_entries[i].path_len + 1);
        memcpy(whitelist_table[node_number].white_entries[i].path, read_whitelist_message + acc, sizeof(u_int8_t) * whitelist_table[node_number].white_entries[i].path_len);
        acc += sizeof(u_int8_t) * whitelist_table[node_number].white_entries[i].path_len;
    }

    free(read_whitelist_message);
}