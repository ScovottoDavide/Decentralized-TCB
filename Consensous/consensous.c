#include "consensous.h"

void hex_print(uint8_t *raw_data, size_t raw_size) {
  int i;

  for(i = 0; i < raw_size; i++)
    fprintf(stdout, "%02X", raw_data[i]);
}

int get_index_from_digest(STATUS_TABLE *status_table, uint8_t digest[SHA256_DIGEST_LENGTH+1]) {
    int i;
    for(i = 0; i < status_table->number_of_entries; i++) {
        if(memcmp(status_table->status_entries[i].ak_digest, digest, SHA256_DIGEST_LENGTH) == 0){
            return i;
        }   
    }
    return -1;
}

// heartbeat --> NULL to my_local_status, nodes_number = full (ex 4 = have received 4 local trust status)
int consensous_proc(STATUS_TABLE *my_local_trust_status, STATUS_TABLE *others_local_trust_status, STATUS_TABLE *global_trust_status, int nodes_number) {
    int consensous_rule = ((nodes_number) / 2) + 1;
    int i, j, inserted_global = 0, k;

    fprintf(stdout, "Consensous rule: sum(T) >= %d\n", consensous_rule);

    // prepare the global table
    for(i = 0; i < nodes_number; i++) {
        for(j = 0; j < others_local_trust_status[i].number_of_entries; j++) {
            if(get_index_from_digest(global_trust_status, others_local_trust_status[i].status_entries[j].ak_digest) == -1){
                memcpy(global_trust_status->status_entries[inserted_global].ak_digest, others_local_trust_status[i].status_entries[j].ak_digest, SHA256_DIGEST_LENGTH);
                global_trust_status->status_entries[inserted_global].ak_digest[SHA256_DIGEST_LENGTH] = '\0';
                inserted_global += 1;
            }
        }
    }

    // calculate overall trust
    for(i = 0; i < nodes_number; i++) {
        for(j = 0; j < others_local_trust_status[i].number_of_entries; j++) {
            k = get_index_from_digest(global_trust_status, others_local_trust_status[i].status_entries[j].ak_digest);
            if(k >= 0){
                if(others_local_trust_status[i].status_entries[j].status == 1)
                    global_trust_status->status_entries[k].status += 1;
            }
        }
    }

    // Last pass on global
    for(i = 0; i < global_trust_status->number_of_entries; i++) {
        if(global_trust_status->status_entries[i].status >= consensous_rule)
            global_trust_status->status_entries[i].status = 1;
        else 
            global_trust_status->status_entries[i].status = 0;
    }
    return 1;
}