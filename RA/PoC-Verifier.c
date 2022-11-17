#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/rand.h>
#include "whitelist_verify.h"
#include "/home/pi/WAM/WAM.h"

bool legal_int(const char *str);
void hex_print(uint8_t *raw_data, size_t raw_size);
bool openAKPub(const char *path, unsigned char **akPub);
int computePCRsoftBinding(unsigned char *pcr_concatenated, const char *sha_alg, unsigned char *digest, int size);
bool PCR9_calculation(unsigned char *expected_PCR9sha1, unsigned char *expected_PCR9sha256, AK_FILE_TABLE *ak_table,
            TO_SEND TpaData, int nodes_number);
void get_Index_from_file(FILE *index_file, IOTA_Index *heartBeat_index, IOTA_Index *write_index, 
      IOTA_Index *read_indexes, IOTA_Index *read_indexes_AkPub, IOTA_Index *read_indexes_whitelist, int nodes_number);
void parseTPAdata(TO_SEND *TpaData, uint8_t *read_attest_message, int node_number);
void sendRAresponse(WAM_channel *ch_send, VERIFICATION_RESPONSE *ver_response, int nodes_number);

typedef struct {
  const char *index_file_path_name;
  int nodes_number;
}ARGS;
void menu(void *in);
void PoC_Verifier(void *input);

volatile int verifier_status = 0; // 0 -> do not stop; 1 --> stop the process
volatile int early_exit = 0;
pthread_mutex_t menuLock;

int main(int argc, char const *argv[]) {
  ARGS *args = malloc(sizeof(ARGS)); 
  pthread_t th_verifier, th_menu;

  if(argc != 3){
    fprintf(stdout, "Please specify the file path and the number of nodes\n");
    return -1;
  }    
  if(atoi(argv[2]) < 0 || !legal_int(argv[2])){
    fprintf(stdout, "Entered parameter is NaN or it has to be greater than 0\n");
    return -1;
  }
  args->index_file_path_name = argv[1];
  args->nodes_number = atoi(argv[2]);

  pthread_create(&th_verifier, NULL, (void *)&PoC_Verifier, (void *) args);
  pthread_create(&th_menu, NULL, (void *)&menu, NULL);

  pthread_join(th_verifier, NULL);
  if(early_exit)
    pthread_cancel(th_menu);
  pthread_join(th_menu, NULL);
  return 0;
}

void menu(void *in) {
    int input;
    fprintf(stdout, "Press [1] --> Stop Verifier\n");
    fscanf(stdin, "%d", &input);
    if(input == 1){
        pthread_mutex_lock(&menuLock); // Lock a mutex for heartBeat_Status
        fprintf(stdout, "Waiting to process the last data. Gracefully stopping the Verifier!\n");
        verifier_status = 1;
        pthread_mutex_unlock(&menuLock); // Unlock a mutex for heartBeat_Status
    }
}

void PoC_Verifier(void *input){
  int nodes_number = ((ARGS *)input)->nodes_number;
  const char *file_index_path_name = ((ARGS *)input)->index_file_path_name;
  int i, j, *verified_nodes;
  TO_SEND *TpaData; VERIFICATION_RESPONSE *ver_response; AK_FILE_TABLE *ak_table; NONCE_BLOB nonce_blob;
  WHITELIST_TABLE *whitelist_table; PCRS_MEM *pcrs_mem;
  FILE *index_file, **ak_files;
  
  IOTA_Index heartBeat_index, *read_indexes = NULL, *read_indexes_AkPub = NULL, *read_indexes_whitelist = NULL, write_response_index;
  uint8_t mykey[]="supersecretkeyforencryptionalby";
	WAM_channel ch_read_hearbeat, *ch_read_attest, ch_write_response, *ch_read_ak, *ch_read_whitelist;
	WAM_AuthCtx a; a.type = AUTHS_NONE;
	WAM_Key k; k.data = mykey; k.data_len = (uint16_t) strlen((char*)mykey);
	
  uint32_t expected_size = 32, expected_size_attest_message = DATA_SIZE, *offset;
	uint8_t ret = 0, **read_attest_message = NULL, expected_attest_message[DATA_SIZE], have_to_read = 0, nonce[32], last[4] = "done";
  uint16_t *previous_msg_num;

  unsigned char *pcr9_sha1 = NULL, *pcr9_sha256 = NULL;

  TpaData = malloc(nodes_number * sizeof(TO_SEND));
  ver_response = malloc(nodes_number * sizeof(VERIFICATION_RESPONSE));
  ak_table = malloc(nodes_number * sizeof(AK_FILE_TABLE));
  whitelist_table = malloc(nodes_number * sizeof(WHITELIST_TABLE));
  pcrs_mem = malloc(nodes_number * sizeof(PCRS_MEM));

  ch_read_attest = malloc(nodes_number * sizeof(WAM_channel));
  ch_read_ak = malloc(nodes_number * sizeof(WAM_channel));
  ch_read_whitelist = malloc(nodes_number * sizeof(WAM_channel));

  read_indexes = malloc(nodes_number * sizeof(IOTA_Index));
  read_indexes_AkPub = malloc(nodes_number * sizeof(IOTA_Index));
  read_indexes_whitelist = malloc(nodes_number * sizeof(IOTA_Index));

  ak_files = malloc(nodes_number * sizeof(FILE *));
  offset = malloc(nodes_number * sizeof(uint32_t));
  previous_msg_num = malloc(nodes_number * sizeof(uint16_t));
  verified_nodes = calloc(nodes_number, sizeof(int));

  for(i = 0; i < nodes_number; i++){
    pcrs_mem[i].pcr10_sha1 = calloc((SHA_DIGEST_LENGTH + 1), sizeof(unsigned char));
    pcrs_mem[i].pcr10_sha256 = calloc((SHA256_DIGEST_LENGTH + 1), sizeof(unsigned char));
  }
  pcr9_sha1 = malloc((SHA_DIGEST_LENGTH + 1) * sizeof(unsigned char));
  pcr9_sha256 = malloc((SHA256_DIGEST_LENGTH + 1) * sizeof(unsigned char));

  IOTA_Endpoint privatenet = {.hostname = "130.192.86.15\0",
							 .port = 14000,
							 .tls = false};

  index_file = fopen(file_index_path_name, "r");
  if(index_file == NULL){
    fprintf(stdout, "Cannot open index file\n");
    return ;
  }
  get_Index_from_file(index_file, &heartBeat_index, &write_response_index, read_indexes, read_indexes_AkPub, read_indexes_whitelist, nodes_number);
  fclose(index_file);

  // Set read index of heartbeat
  WAM_init_channel(&ch_read_hearbeat, 1, &privatenet, &k, &a);
	set_channel_index_read(&ch_read_hearbeat, heartBeat_index.index);
  // Set indexes for reading TpaData
  for(i = 0; i < nodes_number; i++){
    WAM_init_channel(&ch_read_attest[i], i, &privatenet, &k, &a);
    set_channel_index_read(&ch_read_attest[i], read_indexes[i].index);
  }
  // Set indexes for reading Tpas AK
  for(i = 0; i < nodes_number; i++){
    WAM_init_channel(&ch_read_ak[i], i, &privatenet, &k, &a);
    set_channel_index_read(&ch_read_ak[i], read_indexes_AkPub[i].index);
  }
  // Set indexes for reading Tpas whitelists
  for(i = 0; i < nodes_number; i++){
    WAM_init_channel(&ch_read_whitelist[i], i, &privatenet, &k, &a);
    set_channel_index_read(&ch_read_whitelist[i], read_indexes_whitelist[i].index);
  }

  // Set write index for response to heartbeat 
  WAM_init_channel(&ch_write_response, 1, &privatenet, &k, &a);
  set_channel_index_write(&ch_write_response, write_response_index);

  // First get all the AKs and construct table in order to recognize each TpaData received from the various Tpas
  cleanUpFolder("/etc/tc/TPA_AKs");
  srand((unsigned int)(time(NULL)));
  for(i = 0; i < nodes_number; i++){
    int res = read_and_save_AKs(&ch_read_ak[i], ak_table, ak_files[i], i, &verifier_status, menuLock);
    if(res < 0){
      fprintf(stdout, "Verifier Stopped while waiting for AK pubs of TPAs\n");
      goto early_end;
    }
  }
  fprintf(stdout, "AK map constructed\n");

  for(i = 0; i < nodes_number; i++){
    if(!read_and_save_whitelist(&ch_read_whitelist[i], whitelist_table, i))
      goto early_end;
  }
  fprintf(stdout, "Whitelist map constructed\n");

  for(i = 0; i < nodes_number; i++){
    preparePCRSmap(pcrs_mem, ak_table, i);
  }
  fprintf(stdout, "PCRS map constructed\n");

  for(i = 0; i < nodes_number; i++){
    ver_response[i].number_white_entries = 0;
    // THE MAX NUMBER OF UNTRUSTED ENTRIES = THE NUMBER OF WHITELIST ENTRIES (WORST SCENARIO)
    ver_response[i].untrusted_entries = malloc(whitelist_table[i].number_of_entries * sizeof(UNTRUSTED_PATH));
  }

  // Construct a whitelist map --> each verification has to be done w.r.t. the whitelist of the attested node.
  // Each node/TPA is recognized thanks to the hash of the public key read from the previous step
  // Read the whitelist from the tangle! So every TPA has to upload its whitelist before the process starts

  fprintf(stdout, "\n Reading...\n");
  read_attest_message = (uint8_t **) malloc(nodes_number * sizeof(uint8_t *));
  for(i = 0; i < nodes_number; i++)
    read_attest_message[i] = (uint8_t *) malloc(sizeof(uint8_t) * (1024 * 100 * 2));

  while(!WAM_read(&ch_read_hearbeat, nonce, &expected_size)){
    if(ch_read_hearbeat.recv_bytes == expected_size && !have_to_read){
      // new nonce arrived --> read new attestations
      expected_size+=32;
      have_to_read = 1;

      for(i = 0; i < nodes_number; i++){
        ch_read_attest[i].recv_bytes = 0;
        ch_read_attest[i].recv_msg = 0;
        offset[i] = 0;
        previous_msg_num[i] = 0;
      }
      nonce_blob.tag = (u_int8_t)0;
      nonce_blob.size = sizeof nonce;
      memcpy(nonce_blob.buffer, nonce, nonce_blob.size);
    }
    i = 0;
    while(have_to_read > 0){
      if(verified_nodes[i] == 0){
        if(!WAM_read(&ch_read_attest[i], expected_attest_message, &expected_size_attest_message)){            
          if(ch_read_attest[i].recv_msg != previous_msg_num[i]) {
            memcpy(read_attest_message[i] + offset[i], expected_attest_message, DATA_SIZE);
            offset[i] += DATA_SIZE;
            previous_msg_num[i] += 1;
          } 
          else if(memcmp(last, read_attest_message[i] + ch_read_attest[i].recv_bytes - sizeof last, sizeof last) == 0){
            parseTPAdata(TpaData, read_attest_message[i], i);
            fprintf(stdout, "\tNew quote from [%d bytes]: ", ch_read_attest[i].recv_bytes); hex_print(TpaData[i].ak_digest_blob.buffer, SHA256_DIGEST_LENGTH);
            have_to_read += 1;

            // Get also pcr10 since we're reading pcrs here
            fprintf(stdout, "Calculating PCR9s ...\n");
            if (!PCR9_calculation(pcr9_sha1, pcr9_sha256, ak_table, TpaData[i], nodes_number)) {
              fprintf(stderr, "PCR9 calculation failed\n");
              goto end;
            }

            // PCR10 calculation + whitelist verify
            int white_index = getIndexFromDigest(TpaData[i].ak_digest_blob.buffer, whitelist_table, nodes_number);
            if(white_index < 0){
              fprintf(stdout, "Error while retrieving correct whitelist from TPA Ak digest\n");
              goto end;
            }
            int pcrs_index = getIndexForPCR(pcrs_mem, TpaData[i].ak_digest_blob.buffer, nodes_number);
            if(pcrs_index < 0){
              fprintf(stdout, "Could not retrieve the correct old pcr");
              goto end;
            }
            memcpy(&ver_response[i].ak_digest, whitelist_table[white_index].ak_digest, SHA256_DIGEST_LENGTH);
            ver_response[i].ak_digest[SHA256_DIGEST_LENGTH] = '\0';
            fprintf(stdout, "Calculating PCR10s and performing whitelist checks...\n");
            if(!verify_PCR10_whitelist(pcrs_mem[pcrs_index].pcr10_sha1, pcrs_mem[pcrs_index].pcr10_sha256, TpaData[i].ima_log_blob, &ver_response[i], whitelist_table[white_index])){
              fprintf(stdout, "Error while calculating pcr10s or verifying whitelist\n");
              goto end;
            }

            if (!tpm2_checkquote(TpaData[i], nonce_blob, ak_table, nodes_number, pcrs_mem[pcrs_index].pcr10_sha256, pcrs_mem[pcrs_index].pcr10_sha1, pcr9_sha256, pcr9_sha1)) {
              ver_response[i].is_quote_successful = 0;
              fprintf(stdout, "Quote verification failed!!!!\n");
            } else{
              ver_response[i].is_quote_successful = 1;
              fprintf(stdout, "Quote successfully verified!!!!\n");
            } 

            fprintf(stdout, "Verification response built for: "); hex_print(ver_response[i].ak_digest, SHA256_DIGEST_LENGTH);
            for(j = 0; j < ver_response[i].number_white_entries; j++)
              if(ver_response[i].untrusted_entries[j].name_len != 0)
                fprintf(stdout, "path: %s\n", ver_response[i].untrusted_entries[j].untrusted_path_name);

            verified_nodes[i] = 1;
              
            for(j = 0; j < TpaData[i].ima_log_blob.size; j++){
              free(TpaData[i].ima_log_blob.logEntry[j].template_data);
            }
            free(TpaData[i].ima_log_blob.logEntry);
          }
        }
        if(have_to_read == nodes_number + 1){ // +1 because have_to_read start count from 1
          // write "response" to heartbeat
          fprintf(stdout, "Sending verification response... \n");
          sendRAresponse(&ch_write_response, ver_response, nodes_number);
          have_to_read = 0;
          for(j = 0; j < nodes_number; j++)
            verified_nodes[j] = 0;
        }
      }
      if((i + 1) == nodes_number) i = 0;
      else i+=1;
      pthread_mutex_lock(&menuLock); // Lock a mutex for heartBeat_Status
      if(verifier_status == 1){ // stop
        fprintf(stdout, "Verifier Stopped\n");
        pthread_mutex_unlock(&menuLock); // Unlock a mutex for heartBeat_Status
        goto end;
      }
      pthread_mutex_unlock(&menuLock); // Unlock a mutex for heartBeat_Status
    }
    pthread_mutex_lock(&menuLock); // Lock a mutex for heartBeat_Status
    if(verifier_status == 1){ // stop
      fprintf(stdout, "Verifier Stopped\n");
      pthread_mutex_unlock(&menuLock); // Unlock a mutex for heartBeat_Status
      goto end;
    }
    pthread_mutex_unlock(&menuLock); // Unlock a mutex for heartBeat_Status
  }
  
end:
  for(i = 0; i < nodes_number; i++)
      free(read_attest_message[i]);
  if(read_attest_message != NULL) free(read_attest_message);
  for(i = 0; i < nodes_number; i++){
    free(TpaData[i].sig_blob.buffer);
    free(TpaData[i].message_blob.buffer);
    free(TpaData[i].ak_digest_blob.buffer);
    free(ak_table[i].path_name);
    for(j = 0; j < ver_response[i].number_white_entries; j++)
      if(ver_response[i].untrusted_entries[j].name_len > 0) 
        free(ver_response[i].untrusted_entries[j].untrusted_path_name);
    for(j = 0; j < whitelist_table[i].number_of_entries; j++)
      if(whitelist_table[i].white_entries[j].path != NULL)
        free(whitelist_table[i].white_entries[j].path);
    free(whitelist_table[i].white_entries);
    free(ver_response[i].untrusted_entries);
  }
early_end:
  free(TpaData); free(ver_response); free(ak_table); free(whitelist_table);
  for(i = 0; i < nodes_number; i++){
    free(pcrs_mem[i].pcr10_sha1);
    free(pcrs_mem[i].pcr10_sha256);
  }
  free(pcrs_mem);
  free(pcr9_sha1); free(pcr9_sha256);
  free(ch_read_attest); free(ch_read_ak); free(ch_read_whitelist);
  free(read_indexes); free(read_indexes_AkPub); free(read_indexes_whitelist);
  free(ak_files);
  free(offset); free(previous_msg_num);
  free(verified_nodes);
  pthread_mutex_lock(&menuLock); // Lock a mutex for heartBeat_Status
  if(verifier_status == 0){ // stop
    fprintf(stdout, "Verifier Stopped\n");
    early_exit = 1;
  }
  pthread_mutex_unlock(&menuLock); // Unlock a mutex for heartBeat_Status
  return ;
}

bool legal_int(const char *str) {
    while (*str)
        if (!isdigit(*str++))
            return false;
    return true;
}

void get_Index_from_file(FILE *index_file, IOTA_Index *heartBeat_index, IOTA_Index *write_index, 
      IOTA_Index *read_indexes, IOTA_Index *read_indexes_AkPub, IOTA_Index *read_indexes_whitelist, int nodes_number) {
  int len_file, i = 0;
  char *data = NULL, read_index_base_str[20] = "read_index_", akread_index_base_str[20] = "AkPub_read_";
  char akpub_index_base_str[20]="pub_key_", index_AkPub_base_str[25]="AkPub_read_pubkey_";
  char whitelist_index_base_str[30]="whitelist_read_", whitelist_index_read_base_str[40]="whitelist_read_pubkey_";

  //get len of file
  fseek(index_file, 0L, SEEK_END);
  len_file = ftell(index_file);
  fseek(index_file, 0L, SEEK_SET);

  // read the data from the file 
  data = (char*) malloc((len_file + 1)*sizeof(char));
  fread(data, 1, len_file, index_file);
  data[len_file] = '\0';

  cJSON *json = cJSON_Parse(data);
  
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "index")->valuestring, INDEX_HEX_SIZE, write_index->index, INDEX_SIZE);
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "pub_key")->valuestring, (ED_PUBLIC_KEY_BYTES * 2) + 1, write_index->keys.pub, ED_PUBLIC_KEY_BYTES);
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "priv_key")->valuestring, (ED_PRIVATE_KEY_BYTES * 2) + 1, write_index->keys.priv, ED_PRIVATE_KEY_BYTES);

  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "heartbeat")->valuestring, INDEX_HEX_SIZE, heartBeat_index->index, INDEX_SIZE);
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "heartBeat_pub_key")->valuestring, (ED_PUBLIC_KEY_BYTES * 2) + 1, heartBeat_index->keys.pub, ED_PUBLIC_KEY_BYTES);

  for(i = 0; i < nodes_number; i++){
    read_index_base_str[11] = (i + 1) + '0';
    akpub_index_base_str[8] = (i + 1) + '0';
    hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, read_index_base_str)->valuestring, INDEX_HEX_SIZE, read_indexes[i].index, INDEX_SIZE);
    hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, akpub_index_base_str)->valuestring, (ED_PUBLIC_KEY_BYTES * 2) + 1, read_indexes[i].keys.pub, ED_PUBLIC_KEY_BYTES);
  }
  for(i = 0; i < nodes_number; i++){
    akread_index_base_str[11] = (i + 1) + '0';
    index_AkPub_base_str[18] = (i + 1) + '0';
    hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, akread_index_base_str)->valuestring, INDEX_HEX_SIZE, read_indexes_AkPub[i].index, INDEX_SIZE);
    hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, index_AkPub_base_str)->valuestring, (ED_PUBLIC_KEY_BYTES * 2) + 1, read_indexes_AkPub[i].keys.pub, ED_PUBLIC_KEY_BYTES);
  }
  for(i = 0; i < nodes_number; i++){
    whitelist_index_base_str[15] = (i + 1) + '0';
    whitelist_index_read_base_str[22] = (i + 1) + '0';
    hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, whitelist_index_base_str)->valuestring, INDEX_HEX_SIZE, read_indexes_whitelist[i].index, INDEX_SIZE);
    hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, whitelist_index_read_base_str)->valuestring, (ED_PUBLIC_KEY_BYTES * 2) + 1, read_indexes_whitelist[i].keys.pub, ED_PUBLIC_KEY_BYTES);
  }
  
  free(data);
  cJSON_Delete(json);
}

void parseTPAdata(TO_SEND *TpaData, uint8_t *read_attest_message, int node_number) {
  int acc = 0, i;

  // SIG
  memcpy(&TpaData[node_number].sig_blob.tag, read_attest_message + acc, sizeof(u_int8_t));
  acc += sizeof(u_int8_t);
  memcpy(&TpaData[node_number].sig_blob.size, read_attest_message + acc, sizeof(u_int16_t));
  acc += sizeof(u_int16_t);
  TpaData[node_number].sig_blob.buffer = malloc(TpaData[node_number].sig_blob.size + 1 * sizeof(u_int8_t));
  memcpy(TpaData[node_number].sig_blob.buffer, read_attest_message + acc, sizeof(u_int8_t) * TpaData[node_number].sig_blob.size);
  TpaData[node_number].sig_blob.buffer[TpaData[node_number].sig_blob.size] = '\0';
  acc += sizeof(u_int8_t) * TpaData[node_number].sig_blob.size;
  
  // MESSAGE
  memcpy(&TpaData[node_number].message_blob.tag, read_attest_message + acc, sizeof(u_int8_t));
  acc += sizeof(u_int8_t);
  memcpy(&TpaData[node_number].message_blob.size, read_attest_message + acc, sizeof(u_int16_t));
  acc += sizeof(u_int16_t);
  TpaData[node_number].message_blob.buffer = malloc(TpaData[node_number].message_blob.size + 1 * sizeof(u_int8_t));
  memcpy(TpaData[node_number].message_blob.buffer, read_attest_message + acc, sizeof(u_int8_t) * TpaData[node_number].message_blob.size);
  TpaData[node_number].message_blob.buffer[TpaData[node_number].message_blob.size] = '\0';
  acc += sizeof(u_int8_t) * TpaData[node_number].message_blob.size;

  // IMA
  memcpy(&TpaData[node_number].ima_log_blob.tag, read_attest_message + acc, sizeof(u_int8_t));
  acc += sizeof(u_int8_t);
  memcpy(&TpaData[node_number].ima_log_blob.size, read_attest_message + acc, sizeof(u_int16_t));
  acc += sizeof(u_int16_t);
  memcpy(&TpaData[node_number].ima_log_blob.wholeLog, read_attest_message + acc, sizeof(u_int8_t));
  acc += sizeof(u_int8_t);
  
  TpaData[node_number].ima_log_blob.logEntry = calloc(TpaData[node_number].ima_log_blob.size, sizeof(struct event));

  for (i = 0; i < TpaData[node_number].ima_log_blob.size; i++) {
    // send header
    memcpy(&TpaData[node_number].ima_log_blob.logEntry[i].header, read_attest_message + acc, sizeof TpaData[node_number].ima_log_blob.logEntry[i].header);
    acc += sizeof TpaData[node_number].ima_log_blob.logEntry[i].header;
    // send name
    memcpy(TpaData[node_number].ima_log_blob.logEntry[i].name, read_attest_message + acc, TpaData[node_number].ima_log_blob.logEntry[i].header.name_len * sizeof(char));
    acc += TpaData[node_number].ima_log_blob.logEntry[i].header.name_len * sizeof(char);
    // send template data len
    memcpy(&TpaData[node_number].ima_log_blob.logEntry[i].template_data_len, read_attest_message + acc, sizeof(u_int32_t));
    acc += sizeof(u_int32_t);
    // send template data
    TpaData[node_number].ima_log_blob.logEntry[i].template_data = malloc(TpaData[node_number].ima_log_blob.logEntry[i].template_data_len + 1 * sizeof(u_int8_t));
    memcpy(TpaData[node_number].ima_log_blob.logEntry[i].template_data, read_attest_message + acc, TpaData[node_number].ima_log_blob.logEntry[i].template_data_len * sizeof(u_int8_t));
    acc += TpaData[node_number].ima_log_blob.logEntry[i].template_data_len * sizeof(u_int8_t);
    TpaData[node_number].ima_log_blob.logEntry[i].template_data[TpaData[node_number].ima_log_blob.logEntry[i].template_data_len] = '\0';
  }
  // AK MD
  memcpy(&TpaData[node_number].ak_digest_blob.tag, read_attest_message + acc, sizeof(u_int8_t));
  acc += sizeof(u_int8_t);
  memcpy(&TpaData[node_number].ak_digest_blob.size, read_attest_message + acc, sizeof(u_int16_t));
  acc += sizeof(u_int16_t);
  TpaData[node_number].ak_digest_blob.buffer = malloc(TpaData[node_number].ak_digest_blob.size + 1 * sizeof(u_int8_t));
  memcpy(TpaData[node_number].ak_digest_blob.buffer, read_attest_message + acc, sizeof(u_int8_t) * TpaData[node_number].ak_digest_blob.size);
  TpaData[node_number].ak_digest_blob.buffer[TpaData[node_number].ak_digest_blob.size] = '\0';
}

void sendRAresponse(WAM_channel *ch_send, VERIFICATION_RESPONSE *ver_response, int nodes_number){
  size_t acc = 0, bytes_to_send = 0;
  int i, j;
  uint8_t last[4] = "done", *response_buff = NULL;
  
  for(i = 0; i < nodes_number; i++){
    bytes_to_send += (sizeof(uint8_t)*SHA256_DIGEST_LENGTH) + sizeof(uint16_t) + sizeof(uint8_t); // tag + number of untrsuted entries + is_quote_successful
    for(j = 0; j < ver_response[i].number_white_entries; j++){
      bytes_to_send += sizeof(uint16_t);
      bytes_to_send += ver_response[i].untrusted_entries[j].name_len * sizeof(char);
    }
  }
  bytes_to_send += sizeof last;

  response_buff = malloc(sizeof(uint8_t) * bytes_to_send);
  if(response_buff == NULL){
    fprintf(stdout, "OOM\n");
    return;
  }

  for(i = 0; i < nodes_number; i++){
    memcpy(response_buff + acc, &ver_response[i].ak_digest, sizeof(uint8_t)*SHA256_DIGEST_LENGTH);
    acc += sizeof(uint8_t)*SHA256_DIGEST_LENGTH;
    memcpy(response_buff + acc, &ver_response[i].number_white_entries, sizeof(uint16_t));
    acc += sizeof(uint16_t);
    memcpy(response_buff + acc, &ver_response[i].is_quote_successful, sizeof(uint8_t));
    acc += sizeof(uint8_t);
    for(j = 0; j < ver_response[i].number_white_entries; j++){
      if(ver_response[i].untrusted_entries[j].name_len > 0 ){
        memcpy(response_buff + acc, &ver_response[i].untrusted_entries[j].name_len, sizeof(uint16_t));
        acc += sizeof(uint16_t);
        memcpy(response_buff + acc, &ver_response[i].untrusted_entries[j].untrusted_path_name, ver_response[i].untrusted_entries[j].name_len * sizeof(char));
        acc += ver_response[i].untrusted_entries[j].name_len * sizeof(char);
      }
    }
  }
  memcpy(response_buff + acc, last, sizeof last);
  acc += sizeof last;

  WAM_write(ch_send, response_buff, (uint32_t)bytes_to_send, false);
  fprintf(stdout, "DONE WRITING - Sent bytes = %d\n\n", bytes_to_send);
  
  free(response_buff);
}

bool openAKPub(const char *path, unsigned char **akPub) {
  int len_file = 0;
  char *data;
  FILE *ak_pub = fopen(path, "r");
  if(ak_pub == NULL){
    fprintf(stderr, "Could not open file %s \n", path);
    return false;
  }

  //get len of file
  fseek(ak_pub, 0L, SEEK_END);
  len_file = ftell(ak_pub);
  fseek(ak_pub, 0L, SEEK_SET);
  // read the data from the file 
  data = (char*) malloc((len_file + 1)*sizeof(char));
  fread(data, 1, len_file, ak_pub);
  data[len_file] = '\0';

  *akPub = data;
  fclose (ak_pub);
  return true;
}

int computePCRsoftBinding(unsigned char *pcr_concatenated, const char *sha_alg, unsigned char *digest, int size) {
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  unsigned int md_len, i;

  OpenSSL_add_all_digests();

  md = EVP_get_digestbyname(sha_alg);
  if (md == NULL)
  {
    printf("Unknown message digest %s\n", sha_alg);
    return false;
  }

  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, pcr_concatenated, size);
  EVP_DigestFinal_ex(mdctx, digest, &md_len);
  EVP_MD_CTX_free(mdctx);

  return md_len;
}

bool PCR9_calculation(unsigned char *expected_PCR9sha1, unsigned char *expected_PCR9sha256, AK_FILE_TABLE *ak_table,
            TO_SEND TpaData, int nodes_number) {
  int i;
  unsigned char *akPub = NULL, *digest_sha1 = NULL, *digest_sha256 = NULL;
  u_int8_t *ak_path = NULL, *pcr_sha1 = NULL, *pcr_sha256 = NULL;
  
  ak_path = get_ak_file_path(ak_table, TpaData, nodes_number);
  if(ak_path == NULL){
    fprintf(stdout, "Error while getting Ak path\n");
    return false;
  }
  if (!openAKPub(ak_path, &akPub)) {
    fprintf(stderr, "Could not read AK pub\n");
    return false;
  }
  digest_sha1 = malloc((EVP_MAX_MD_SIZE) * sizeof(unsigned char));
  digest_sha256 = malloc((EVP_MAX_MD_SIZE) * sizeof(unsigned char));
  int md_len_sha1 = computeDigestEVP(akPub, "sha1", digest_sha1);
  if (md_len_sha1 <= 0)
    return false;
  int md_len_sha256 = computeDigestEVP(akPub, "sha256", digest_sha256);
  if (md_len_sha256 <= 0)
    return false;

  pcr_sha1 = calloc((SHA_DIGEST_LENGTH * 2 + 1), sizeof(u_int8_t));
  int k = SHA_DIGEST_LENGTH;
  for (i = 0; i < md_len_sha1; i++)
    pcr_sha1[k++] = (u_int8_t)digest_sha1[i];
  pcr_sha1[SHA_DIGEST_LENGTH * 2] = '\0';
  md_len_sha1 = computePCRsoftBinding(pcr_sha1, "sha1", expected_PCR9sha1, SHA_DIGEST_LENGTH * 2);
  if (md_len_sha1 <= 0)
    return false;

  pcr_sha256 = calloc(SHA256_DIGEST_LENGTH * 2 + 1, sizeof(u_int8_t));
  k = SHA256_DIGEST_LENGTH;
  for (i = 0; i < md_len_sha256; i++) 
    pcr_sha256[k++] = digest_sha256[i];
  pcr_sha256[SHA256_DIGEST_LENGTH * 2] = '\0';
  md_len_sha256 = computePCRsoftBinding(pcr_sha256, "sha256", expected_PCR9sha256, SHA256_DIGEST_LENGTH * 2);
  if (md_len_sha256 <= 0)
    return false;

  free(pcr_sha1);
  free(digest_sha1);
  free(pcr_sha256);
  free(digest_sha256);
  // do not free ak_path because it points to the actual path, otherwise it will free the actual data and the so it will be lost
  return true;
}

void hex_print(uint8_t *raw_data, size_t raw_size){
  int i;

  for(i = 0; i < raw_size; i++)
    fprintf(stdout, "%02X", raw_data[i]);
  fprintf(stdout, "\n");
}