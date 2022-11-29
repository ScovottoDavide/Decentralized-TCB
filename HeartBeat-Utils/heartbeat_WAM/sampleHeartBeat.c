#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/rand.h>
#include "WAM/WAM.h"
#include "../../Consensous/consensous.h"

#define NONCE_LEN 32

void parseLocalTrustStatusMessage(uint8_t *read_trust_message, STATUS_TABLE *read_local_trust_status, int node_number);
void menu(void *in);
void PoC_heartbeat(void *nodes_number_p);
bool legal_int(const char *str);
int my_gets_avoid_bufferoverflow(char *buffer, size_t buffer_len);

volatile int heartBeat_status = 0; // 0 -> do not stop; 1 --> stop the process
volatile int early_exit = 0;
pthread_mutex_t menuLock, earlyLock;

int main(int argc, char *argv[]) {
    int nodes_number;
    pthread_t th_heartbeat, th_menu;
    if(argc != 2){
        fprintf(stdout, "Usage: ./WAM_heartbeat (number of verifier nodes)\n");
        return -1;
    }
    if(atoi(argv[1]) <= 0 || !legal_int(argv[1])){
        fprintf(stdout, "Entered parameter is NaN or it has to be greater than 0\n");
        return -1;
    }
    nodes_number = atoi(argv[1]);
    pthread_create(&th_heartbeat, NULL, (void *)&PoC_heartbeat, &nodes_number);
    pthread_create(&th_menu, NULL, (void *)&menu, NULL);

    pthread_join(th_heartbeat, NULL);
    pthread_mutex_lock(&earlyLock);
    if(early_exit){
        pthread_mutex_unlock(&earlyLock);
        pthread_cancel(th_menu);
    }
    pthread_join(th_menu, NULL);
    return 0;
}

bool legal_int(const char *str) {
    while (*str)
        if (!isdigit(*str++))
            return false;
    return true;
}

int my_gets_avoid_bufferoverflow(char *buffer, size_t buffer_len) {
    // Clear buffer to ensure the string will be null terminated
    memset(buffer, 0, buffer_len);

    int c;
    int bytes_read = 0;
    // Read one char at a time until EOF or newline
    while (EOF != (c = fgetc(stdin)) && '\n' != c) {
        // Only add to buffer if within size limit
        if (bytes_read < buffer_len - 1) {
            buffer[bytes_read++] = (char)c;
        }
    }
    return bytes_read;
}

void menu(void *in) {
    char input[10];
    do{
        fprintf(stdout, "Press [1] --> Stop Heartbeat\n");
        my_gets_avoid_bufferoverflow(input, sizeof(input));
        if(atoi(input) == 1){
            pthread_mutex_lock(&menuLock); // Lock a mutex for heartBeat_Status
            heartBeat_status = 1;
            pthread_mutex_unlock(&menuLock); // Unlock a mutex for heartBeat_Status
        }
    } while(atoi(input) != 1);
}

void PoC_heartbeat(void *nodes_number_p) {
    int nodes_number = *((int *)nodes_number_p);
	uint8_t mykey[]="supersecretkeyforencryptionalby", nonce[NONCE_LEN], expected_response_messages[DATA_SIZE];
    uint8_t last[4] = "done", **read_response_messages;
	uint32_t expected_response_size = DATA_SIZE, offset[nodes_number], previous_msg_num[nodes_number];
	WAM_AuthCtx a; a.type = AUTHS_NONE;
	WAM_Key k; k.data = mykey; k.data_len = (uint16_t) strlen((char*)mykey);
    STATUS_TABLE *read_local_trust_status, global_trust_status;
	
    FILE *index_file;
    int len_file, i, new_nonce_send = 1, received_responses = 0, *responses_map, max_number_trust_entries = 0;
    char *data = NULL, prefix_str_index[12]="read_index_", prefix_str_pubK[9]="pub_key_", buf_index_str[100] = {0};

    IOTA_Index file_index, *read_response_indexes;
    WAM_channel ch_send, *ch_read_responses;

    IOTA_Endpoint privatenet = {.hostname = "130.192.86.15",
							 .port = 14000,
							 .tls = false};

    // read the pre-allocated indexes from the file
    index_file = fopen("heartbeat_write.json", "r");
    if(index_file == NULL) {
        fprintf(stdout, "Heartbeat Index file missing!\n");
        goto early_end;
    }
        //get len of file
    fseek(index_file, 0, SEEK_END);
    len_file = ftell(index_file);
    fseek(index_file, 0, SEEK_SET);
        // read the data from the file 
    data = (char*) malloc(len_file + 1 * sizeof(char));
    fread(data, 1, len_file, index_file);
    data[len_file] = '\0';
    fclose(index_file);

    cJSON *json = cJSON_Parse(data);

    read_response_indexes = malloc(nodes_number * sizeof(IOTA_Index));

    hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "index")->valuestring, INDEX_HEX_SIZE, file_index.index, INDEX_SIZE);
    hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "pub_key")->valuestring, (ED_PUBLIC_KEY_BYTES * 2) + 1, file_index.keys.pub, ED_PUBLIC_KEY_BYTES);
    hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "priv_key")->valuestring, (ED_PRIVATE_KEY_BYTES * 2) + 1, file_index.keys.priv, ED_PRIVATE_KEY_BYTES);

    for(i = 0; i<nodes_number; i++){
        snprintf(buf_index_str, 100, "%s%d", prefix_str_index, i+1);
        hex_2_bin( cJSON_GetObjectItemCaseSensitive(json, buf_index_str)->valuestring, INDEX_HEX_SIZE, read_response_indexes[i].index, INDEX_SIZE);
        snprintf(buf_index_str, 100, "%s%d", prefix_str_pubK, i+1);
        hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, buf_index_str)->valuestring, (ED_PUBLIC_KEY_BYTES * 2) + 1, read_response_indexes[i].keys.pub, ED_PUBLIC_KEY_BYTES);
    }   

    // Set write index read from the file
    WAM_init_channel(&ch_send, 1, &privatenet, &k, &a);
    set_channel_index_write(&ch_send, file_index);

    ch_read_responses = malloc(nodes_number * sizeof(WAM_channel));
    // Set read indexes read from the file
    for(i = 0; i < nodes_number; i++){
        WAM_init_channel(&ch_read_responses[i], i, &privatenet, &k, &a);
        set_channel_index_read(&ch_read_responses[i], read_response_indexes[i].index);
    }

    read_response_messages = (uint8_t**) malloc(nodes_number * sizeof(uint8_t *));
    for(i = 0; i<nodes_number; i++)
        read_response_messages[i] = (uint8_t *) malloc(DATA_SIZE * 2 * sizeof(uint8_t));
    responses_map = calloc(nodes_number, sizeof(int));

    read_local_trust_status = malloc(nodes_number * sizeof(STATUS_TABLE));

    while(1){
        if(new_nonce_send){
            if (!RAND_bytes(nonce, NONCE_LEN)) {
                return;
            } else {
                nonce[NONCE_LEN] = '\0';
                printf("NONCE: ");
                for (i = 0; i < NONCE_LEN; i++)
                    printf("%02x", nonce[i]);
                printf("\n");
                WAM_write(&ch_send, nonce, NONCE_LEN, false);   
                fprintf(stdout, "[CH-id=%d] Messages sent: %d (%d bytes)\n", ch_send.id, ch_send.sent_msg, ch_send.sent_bytes);
                new_nonce_send = 0;
            }
            for(i = 0; i < nodes_number; i++){
                ch_read_responses[i].recv_bytes = 0;
                ch_read_responses[i].recv_msg = 0;
                offset[i] = 0;
                previous_msg_num[i] = 0;
            }
        }
        i = 0;
        while(received_responses < nodes_number && !new_nonce_send){
            if(responses_map[i] == 0 && i < nodes_number){
                if(!WAM_read(&ch_read_responses[i], expected_response_messages, &expected_response_size)){
                    if(ch_read_responses[i].recv_msg != previous_msg_num[i]){
                        memcpy(read_response_messages[i] + offset[i], expected_response_messages, DATA_SIZE);
                        offset[i] += DATA_SIZE;
                        previous_msg_num[i] += 1;
                    }
                    else if(memcmp(last, read_response_messages[i] + ch_read_responses[i].recv_bytes - sizeof last, sizeof last) == 0) {
                        fprintf(stdout, "New response arrived of bytes [%d]\n", ch_read_responses[i].recv_bytes);
                        parseLocalTrustStatusMessage(read_response_messages[i], read_local_trust_status, i);
                        if(read_local_trust_status[i].number_of_entries > max_number_trust_entries)
                            max_number_trust_entries = read_local_trust_status[i].number_of_entries;
                        received_responses+=1;
                        responses_map[i] = 1;
                    }
                }
                if(received_responses == nodes_number){
                    // consencous proc
                    global_trust_status.number_of_entries = max_number_trust_entries + 1; // have to consinder the node it self too
                    global_trust_status.status_entries = malloc(global_trust_status.number_of_entries * sizeof(STATUS_ENTRY));
                    for(int j = 0; j < global_trust_status.number_of_entries; j++)
                        global_trust_status.status_entries[j].status = 0;
                    consensous_proc(NULL, read_local_trust_status, &global_trust_status, nodes_number);
                    fprintf(stdout, "Consensous result: \n");
                    for(int j = 0; j < global_trust_status.number_of_entries; j++){
                        if(global_trust_status.status_entries[j].status == 1) {
                            fprintf(stdout, "Node ID: "); hex_print(global_trust_status.status_entries[j].ak_digest, SHA256_DIGEST_LENGTH); fprintf(stdout, " --> T\n");
                        }
                        else{
                            fprintf(stdout, "Node ID: "); hex_print(global_trust_status.status_entries[j].ak_digest, SHA256_DIGEST_LENGTH); fprintf(stdout, " --> NT\n");
                        }
                    }
                    fprintf(stdout, "All responses arrived! Start new cicle.\n");
                    new_nonce_send = 1;
                    received_responses = 0;
                    for(int j = 0; j < nodes_number; j++)
                        responses_map[j] = 0;
                    if(ch_send.sent_bytes >= 32)
                        sleep(10);
                }
            }
            if(i + 1 == nodes_number) i = 0;
                else i+=1;
            pthread_mutex_lock(&menuLock); // Lock a mutex for heartBeat_Status
            if(heartBeat_status == 1){ // stop
                fprintf(stdout, "Stopping...\n");
                pthread_mutex_unlock(&menuLock); // Unlock a mutex for heartBeat_Status
                goto end;
            }
            pthread_mutex_unlock(&menuLock); // Unlock a mutex for heartBeat_Status
        }  
    }
end:
    for(i = 0; i < nodes_number; i++){
        if(read_response_messages[i] != NULL)
            free(read_response_messages[i]);
    }
    if(read_response_messages!=NULL) free(read_response_messages);
    if(responses_map!=NULL) free(responses_map);
    if(data != NULL) free(data);
    if(ch_read_responses != NULL) free(ch_read_responses);
    if(read_response_indexes!= NULL) free(read_response_indexes);
    if(json != NULL) cJSON_Delete(json);
early_end:
    pthread_mutex_lock(&menuLock); // Lock a mutex for heartBeat_Status
    if(heartBeat_status == 0){ // stop
        fprintf(stdout, "Stopping...\n");
        pthread_mutex_lock(&earlyLock); // Lock a mutex for heartBeat_Status
        early_exit = 1;
        pthread_mutex_unlock(&earlyLock); // Unlock a mutex for heartBeat_Status
    }
    pthread_mutex_unlock(&menuLock); // Unlock a mutex for heartBeat_Status
    return ;
}

void parseLocalTrustStatusMessage(uint8_t *read_trust_message, STATUS_TABLE *read_local_trust_status, int node_number) {
    int acc = 0, i;

    memcpy(&read_local_trust_status[node_number].number_of_entries, read_trust_message + acc, sizeof(uint16_t));
    acc += sizeof(uint16_t);
    
    read_local_trust_status[node_number].status_entries = malloc(read_local_trust_status[node_number].number_of_entries * sizeof(STATUS_ENTRY));

    for(i = 0; i < read_local_trust_status[node_number].number_of_entries; i++) {
        memcpy(read_local_trust_status[node_number].status_entries[i].ak_digest, read_trust_message + acc, SHA256_DIGEST_LENGTH * sizeof(uint8_t));
        read_local_trust_status[node_number].status_entries[i].ak_digest[SHA256_DIGEST_LENGTH] = '\0';
        acc += SHA256_DIGEST_LENGTH * sizeof(uint8_t);
        memcpy(&read_local_trust_status[node_number].status_entries[i].status, read_trust_message + acc, sizeof(uint8_t));
        acc += sizeof(uint8_t);
    }
}

