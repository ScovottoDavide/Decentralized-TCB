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

int get_consensus_rule(int nodes_number) {
    return ((nodes_number) / 2) + 1;
}

// heartbeat --> NULL to my_local_status, nodes_number = full (ex 4 = have received 4 local trust status)
int consensous_proc(STATUS_TABLE *my_local_trust_status, STATUS_TABLE *others_local_trust_status, STATUS_TABLE *global_trust_status, int nodes_number) {
    int i, j, inserted_global = 0, k, index_is_nt;
    int *nt_array = calloc(nodes_number, sizeof(int)); 
    
    int consensus_rule = get_consensus_rule(nodes_number);
    fprintf(stdout, "Consensous rule: sum(T) >= %d\n", consensus_rule);

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

    // Detect untrusted tables
    for(i = 0; i < nodes_number; i++) {
        for(j = 0; j < others_local_trust_status[i].number_of_entries; j++) {
            k = get_index_from_digest(global_trust_status, others_local_trust_status[i].status_entries[j].ak_digest);
            if(k >= 0){
                if(others_local_trust_status[i].status_entries[j].status == 0)
                    nt_array[k] += 1;
            } else {
                fprintf(stdout, "Node ID unkown\n");
                return -1;    
            }
        }
    }

    for(i = 0; i < nodes_number; i++) {
        if(nt_array[i] >= consensus_rule){
            global_trust_status->status_entries[i].status = -1; // tag the node id as already NT
            nodes_number -= 1;
            fprintf(stdout, "Detected NT Node!\n");
        }
    }

    // Get new consensus rule
    consensus_rule = get_consensus_rule(nodes_number);
    fprintf(stdout, "Consensous rule: sum(T) >= %d\n", consensus_rule);

    // Calculate overall trust
    for(i = 0; i < nodes_number; i++) {
        index_is_nt = get_index_from_digest(global_trust_status, others_local_trust_status[i].from_ak_digest);
        if(index_is_nt == -1) {
            fprintf(stdout, "Author of local trust status unkown\n");
            return -1;
        }
        if(global_trust_status->status_entries[index_is_nt].status != -1){
            for(j = 0; j < others_local_trust_status[i].number_of_entries; j++) {
            k = get_index_from_digest(global_trust_status, others_local_trust_status[i].status_entries[j].ak_digest);
            if(k >= 0){
                if(others_local_trust_status[i].status_entries[j].status == 1)
                    global_trust_status->status_entries[k].status += 1;
                }
            }
        } else {
            fprintf(stdout, "untrusted %s\n", global_trust_status->status_entries[index_is_nt].ak_digest);
        }
    }

    // Last pass on global
    for(i = 0; i < global_trust_status->number_of_entries; i++) {
        if(global_trust_status->status_entries[i].status >= consensus_rule)
            global_trust_status->status_entries[i].status = 1;
        else 
            global_trust_status->status_entries[i].status = 0;
    }
    return 1;
}