#include "consensous.h"

int get_index_from_digest(STATUS_TABLE *status_table, uint8_t digest[SHA256_DIGEST_LENGTH+1], int number_of_entries) {
    int i;
    for(i = 0; i < number_of_entries; i++) {
        if(memcmp(status_table[i].ak_digest, digest, SHA256_DIGEST_LENGTH) == 0)
            return i;
    }
    return -1;
}

// heartbeat --> NULL to my_local_status, nodes_number = full (ex 4 = have received 4 local trust status), number of entries = in each local trust status how many entries in each table
int consensous_proc(STATUS_TABLE *my_local_trust_status, STATUS_TABLE **others_local_trust_status, STATUS_TABLE *global_trust_status, int nodes_number, int number_of_entries) {
    float consensous_rule = (nodes_number - 1) / 2;
    int i, j, inserted_global = 0, k;

    fprintf(stdout, "Consensous rule: %.2f\n", consensous_rule);

    // prepare the global table
    for(i = 0; i < nodes_number; i++) {
        for(j = 0; j < number_of_entries; j++) {
            if(get_index_from_digest(global_trust_status, others_local_trust_status[i][j].ak_digest, nodes_number) == -1){
                memcpy(global_trust_status[inserted_global].ak_digest, others_local_trust_status[i][j].ak_digest, SHA256_DIGEST_LENGTH);
                global_trust_status[inserted_global].ak_digest[SHA256_DIGEST_LENGTH] = '\0';
                inserted_global += 1;
            }
        }
    }

    // calculate overall trust
    for(i = 0; i < nodes_number; i++) {
        for(j = 0; j < number_of_entries; j++) {
            if(k = get_index_from_digest(global_trust_status, others_local_trust_status[i][j].ak_digest, nodes_number) >= 0){
                if(others_local_trust_status[i][j].status == 1)
                    global_trust_status[k].status += 1;
            }
        }
    }

    // Last pass on global
    for(i = 0; i < inserted_global; i++) {
        if(global_trust_status[i].status > consensous_rule)
            global_trust_status[i].status = 1;
        else 
            global_trust_status[i].status = 0;
    }

}