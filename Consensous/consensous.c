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

void parseLocalTrustStatusMessage(uint8_t *read_trust_message, STATUS_TABLE *read_local_trust_status, int node_number) {
    int acc = 0, i;

    memcpy(&read_local_trust_status[node_number].number_of_entries, read_trust_message + acc, sizeof(uint16_t));
    acc += sizeof(uint16_t);
    memcpy(read_local_trust_status[node_number].from_ak_digest, read_trust_message + acc, SHA256_DIGEST_LENGTH * sizeof(uint8_t));
    read_local_trust_status[node_number].from_ak_digest[SHA256_DIGEST_LENGTH] = '\0';
    acc += SHA256_DIGEST_LENGTH * sizeof(uint8_t);

    read_local_trust_status[node_number].status_entries = malloc(read_local_trust_status[node_number].number_of_entries * sizeof(STATUS_ENTRY));

    for(i = 0; i < read_local_trust_status[node_number].number_of_entries; i++) {
        memcpy(read_local_trust_status[node_number].status_entries[i].ak_digest, read_trust_message + acc, SHA256_DIGEST_LENGTH * sizeof(uint8_t));
        read_local_trust_status[node_number].status_entries[i].ak_digest[SHA256_DIGEST_LENGTH] = '\0';
        acc += SHA256_DIGEST_LENGTH * sizeof(uint8_t);
        memcpy(&read_local_trust_status[node_number].status_entries[i].status, read_trust_message + acc, sizeof(int8_t));
        acc += sizeof(int8_t);
    }
}

int checkNT_in_froms(uint8_t *global_digest, STATUS_TABLE *read_trust_local_status, int nodes_number) {
    int i;
    for(i = 0; i < nodes_number; i++)
        if(memcmp(global_digest, read_trust_local_status[i].from_ak_digest, SHA256_DIGEST_LENGTH) == 0)
            return i;
    return -1;
}


int get_consensus_rule(int nodes_number) {
    return ((nodes_number) / 2) + 1;
}

// heartbeat --> NULL to my_local_status, nodes_number = full (ex 4 = have received 4 local trust status)
int consensous_proc(STATUS_TABLE *others_local_trust_status, STATUS_TABLE *global_trust_status, int nodes_number) {
    int i, j, inserted_global = 0, k, index_is_nt, nt_nodes = 0, already_nt = 0;
    int *nt_array = calloc(nodes_number, sizeof(int)); 
    
    int consensus_rule = get_consensus_rule(nodes_number);

    // prepare the global table
    for(i = 0; i < nodes_number; i++) {
        if(others_local_trust_status[i].status_entries != NULL){
            for(j = 0; j < others_local_trust_status[i].number_of_entries; j++) {
                if(get_index_from_digest(global_trust_status, others_local_trust_status[i].status_entries[j].ak_digest) == -1){
                    memcpy(global_trust_status->status_entries[inserted_global].ak_digest, others_local_trust_status[i].status_entries[j].ak_digest, SHA256_DIGEST_LENGTH);
                    global_trust_status->status_entries[inserted_global].ak_digest[SHA256_DIGEST_LENGTH] = '\0';
                    inserted_global += 1;
                }
            }
        }
    }

    // Detect untrusted tables
    for(i = 0; i < nodes_number; i++) {
        if(others_local_trust_status[i].status_entries != NULL){
            for(j = 0; j < others_local_trust_status[i].number_of_entries; j++) {
                k = get_index_from_digest(global_trust_status, others_local_trust_status[i].status_entries[j].ak_digest);
                if(k >= 0){
                    if(others_local_trust_status[i].status_entries[j].status == 0)
                        nt_array[k] += 1;
                } else {
                    fprintf(stdout, "Node ID unknown\n");
                    return 0;    
                }
            }
        } else already_nt += 1;
    }

    for(i = 0; i < nodes_number; i++) {
        if(nt_array[i] >= consensus_rule){
            global_trust_status->status_entries[i].status = -1; // tag the node id as already NT
            nt_nodes +=1;
            fprintf(stdout, "Detected NT Node! ID: "); hex_print(global_trust_status->status_entries[i].ak_digest, 32); fprintf(stdout, "\n");
        }
    }

    /*for(i = 0; i < global_trust_status->number_of_entries; i++) {
        fprintf(stdout, "Node ID: "); hex_print(global_trust_status->status_entries[i].ak_digest, SHA256_DIGEST_LENGTH); 
        fprintf(stdout, " --> %d\n", global_trust_status->status_entries[i].status);
    }*/

    // Last pass on global
    for(i = 0; i < global_trust_status->number_of_entries; i++) {
        if(global_trust_status->status_entries[i].status >= consensus_rule)
            global_trust_status->status_entries[i].status = 0;
        else 
            global_trust_status->status_entries[i].status = 1;
    }
    return 1;
}