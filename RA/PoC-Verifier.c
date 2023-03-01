#include "load_whitelists.h"
#include "read_akpub.h"
#include "whitelist_verify.h"
#include "tpm2_checkquote.h"

typedef struct {
  const char *index_file_path_name;
  int nodes_number;
}ARGS;

int my_gets_avoid_bufferoverflow(char *buffer, size_t buffer_len);
void menu(void *in);
void PoC_Verifier(void *input);

volatile int verifier_status = 0; // 0 -> do not stop; 1 --> stop the process
volatile int early_exit = 0;
pthread_mutex_t menuLock, earlyLock;

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
  pthread_mutex_lock(&earlyLock);
  if(early_exit){
    pthread_mutex_unlock(&earlyLock);
    pthread_cancel(th_menu);
  }
  pthread_mutex_unlock(&earlyLock);
  pthread_join(th_menu, NULL);
  return 0;
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
    do {
      fprintf(stdout, "Press [1] --> Stop Verifier\n");
      my_gets_avoid_bufferoverflow(input, 10);
      if(atoi(input) == 1){
        pthread_mutex_lock(&menuLock); // Lock a mutex for heartBeat_Status
        fprintf(stdout, "Waiting to process the last data. Gracefully stopping the Verifier!\n");
        verifier_status = 1;
        pthread_mutex_unlock(&menuLock); // Unlock a mutex for heartBeat_Status
      }
    }while(atoi(input) != 1);
}

void PoC_Verifier(void *input){
  int nodes_number = ((ARGS *)input)->nodes_number;
  const char *file_index_path_name = ((ARGS *)input)->index_file_path_name;
  int i, j, *verified_nodes, *attest_messages_sizes, attest_messages_size_increment = 1024 * 10, *invalid_channels_attest, 
    *invalid_channels_status, invalid_table_index, ret = 0;
  TO_SEND *TpaData; VERIFICATION_RESPONSE *ver_response; AK_FILE_TABLE *ak_table; NONCE_BLOB nonce_blob;
  WHITELIST_TABLE *whitelist_table; PCRS_MEM *pcrs_mem;
  STATUS_TABLE local_trust_status;
  FILE *index_file, **ak_files;
  
  IOTA_Index heartBeat_index, *read_indexes = NULL, *read_indexes_AkPub = NULL, *read_indexes_whitelist = NULL, write_response_index, 
    *read_indexes_status = NULL;
  uint8_t mykey[]="supersecretkeyforencryptionalby";
	WAM_channel ch_read_hearbeat, *ch_read_attest, ch_write_response, *ch_read_ak, *ch_read_whitelist, *ch_read_status;
	WAM_AuthCtx a; a.type = AUTHS_NONE;
	WAM_Key k; k.data = mykey; k.data_len = (uint16_t) strlen((char*)mykey);
	
  uint32_t expected_size = 32, expected_size_attest_message = DATA_SIZE, *offset, fixed_nonce_size = 32;
	uint8_t **read_attest_message = NULL, expected_attest_message[DATA_SIZE], have_to_read = 0, nonce[32], last[4] = "done";
  uint8_t my_ak_digest[SHA256_DIGEST_LENGTH+1];
  uint16_t *previous_msg_num;

  unsigned char *pcr9_sha1 = NULL, *pcr9_sha256 = NULL;

  TpaData = malloc(nodes_number * sizeof(TO_SEND));
  ver_response = malloc(nodes_number * sizeof(VERIFICATION_RESPONSE));
  ak_table = malloc(nodes_number * sizeof(AK_FILE_TABLE));
  whitelist_table = malloc(nodes_number * sizeof(WHITELIST_TABLE));
  pcrs_mem = malloc(nodes_number * sizeof(PCRS_MEM));
  local_trust_status.status_entries = malloc(nodes_number * sizeof(STATUS_ENTRY)); 

  ch_read_attest = malloc(nodes_number * sizeof(WAM_channel));
  ch_read_ak = malloc(nodes_number * sizeof(WAM_channel));
  ch_read_whitelist = malloc(nodes_number * sizeof(WAM_channel));
  ch_read_status = malloc(nodes_number * sizeof(WAM_channel));

  read_indexes = malloc(nodes_number * sizeof(IOTA_Index));
  read_indexes_AkPub = malloc(nodes_number * sizeof(IOTA_Index));
  read_indexes_whitelist = malloc(nodes_number * sizeof(IOTA_Index));
  read_indexes_status = malloc(nodes_number * sizeof(IOTA_Index));

  ak_files = malloc(nodes_number * sizeof(FILE *));
  offset = malloc(nodes_number * sizeof(uint32_t));
  previous_msg_num = malloc(nodes_number * sizeof(uint16_t));
  verified_nodes = calloc(nodes_number, sizeof(int));
  attest_messages_sizes = malloc(nodes_number * sizeof(int));
  invalid_channels_attest = calloc(nodes_number, sizeof(int));
  invalid_channels_status = calloc(nodes_number, sizeof(int));
  
  for(i = 0; i < nodes_number; i++) attest_messages_sizes[i] = 1024 * 100 * 2;

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
  get_Index_from_file(index_file, &heartBeat_index, &write_response_index, read_indexes, read_indexes_AkPub, read_indexes_whitelist,
    read_indexes_status, nodes_number);
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
  // Set indexes for reading RAs local status
  for(i = 0; i < nodes_number; i++){
    WAM_init_channel(&ch_read_status[i], i, &privatenet, &k, &a);
    set_channel_index_read(&ch_read_status[i], read_indexes_status[i].index);
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

  read_attest_message = (uint8_t **) malloc(nodes_number * sizeof(uint8_t *));
  for(i = 0; i < nodes_number; i++)
    read_attest_message[i] = (uint8_t *) malloc(sizeof(uint8_t) * attest_messages_sizes[i]);
  
  // Initialize local trust status --> all T before verifying them
   if(!get_my_ak_digest(local_trust_status.from_ak_digest)) {
    fprintf(stdout, "Could not calculate my ak digest\n");
    goto early_end;
  }
  for(i = 0; i < nodes_number; i++)
    local_trust_status.status_entries[i].status = 1;
  local_trust_status.number_of_entries = nodes_number;

  fprintf(stdout, "\n Reading...\n");
  int print_nonce = 0;
  while(1){
    if(!print_nonce){
      fprintf(stdout, "Waiting nonce from "); hex_print(ch_read_hearbeat.read_idx, INDEX_SIZE); fprintf(stdout, "\n");
      print_nonce = 1;
    }
    ret = WAM_read(&ch_read_hearbeat, nonce, &fixed_nonce_size);
    if(!ret){
       if(ch_read_hearbeat.recv_bytes == expected_size && !have_to_read){
        fprintf(stdout, "Nonce received # %d\n", expected_size / 32);
        // new nonce arrived --> read new attestations
        expected_size+=fixed_nonce_size;
        have_to_read = 1;
        print_nonce = 0;

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
    } else if(ret != WAM_NOT_FOUND){
      fprintf(stdout, "Error while reading Nonce\n");
    }
    i = 0;
    while(have_to_read > 0){
      if(verified_nodes[i] == 0 && invalid_channels_attest[i] != 1){ 
        ret = WAM_read(&ch_read_attest[i], expected_attest_message, &expected_size_attest_message);
        if(!ret){            
          if(ch_read_attest[i].recv_msg != previous_msg_num[i]) {
            memcpy(read_attest_message[i] + offset[i], expected_attest_message, DATA_SIZE);
            offset[i] += DATA_SIZE;
            if(offset[i] > attest_messages_sizes[i]){
              attest_messages_sizes[i] += attest_messages_size_increment;
              read_attest_message[i] = realloc(read_attest_message[i], attest_messages_sizes[i] * sizeof(uint8_t));
            }
            previous_msg_num[i] += 1;
          } 
          if(memcmp(last, read_attest_message[i] + ch_read_attest[i].recv_bytes - sizeof last, sizeof last) == 0){
            if(ch_read_attest[i].recv_bytes < attest_messages_sizes[i]){
              attest_messages_sizes[i] = ch_read_attest[i].recv_bytes;
              read_attest_message[i] = realloc(read_attest_message[i], attest_messages_sizes[i] * sizeof(uint8_t));
            }
            parseTPAdata(TpaData, read_attest_message[i], i);
            //fprintf(stdout, "\tNew quote from [%d bytes]: ", ch_read_attest[i].recv_bytes); hex_print(TpaData[i].ak_digest_blob.buffer, SHA256_DIGEST_LENGTH);
            have_to_read += 1;

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
            if(TpaData[i].ima_log_blob.wholeLog == 1){ // If whole log is sent reset to 0 the pcrs otherwise checkquote will always fail after 1st round
              memset(pcrs_mem[pcrs_index].pcr10_sha256, 0, SHA256_DIGEST_LENGTH);
              memset(pcrs_mem[pcrs_index].pcr10_sha1, 0, SHA_DIGEST_LENGTH);
            }
            //fprintf(stdout, "Calculating PCR10s and performing whitelist checks...\n");
            if(!verify_PCR10_whitelist(pcrs_mem[pcrs_index].pcr10_sha1, pcrs_mem[pcrs_index].pcr10_sha256, TpaData[i].ima_log_blob, &ver_response[i], whitelist_table[white_index])){
              fprintf(stdout, "Error while calculating pcr10s or verifying whitelist\n");
              goto end;
            }

            if(!tpm2_checkquote(TpaData[i], nonce_blob, ak_table, nodes_number, pcrs_mem[pcrs_index].pcr10_sha256, pcrs_mem[pcrs_index].pcr10_sha1, pcr9_sha256, pcr9_sha1))
              ver_response[i].is_quote_successful = 0;
            else ver_response[i].is_quote_successful = 1; 

            verified_nodes[i] = 1;
            memcpy(local_trust_status.status_entries[i].ak_digest, TpaData[i].ak_digest_blob.buffer, SHA256_DIGEST_LENGTH * sizeof(uint8_t));
            local_trust_status.status_entries[i].ak_digest[SHA256_DIGEST_LENGTH] = '\0';
            if(ver_response[i].is_quote_successful == 1 && ver_response[i].number_white_entries == 0)
              local_trust_status.status_entries[i].status = 1;
            else local_trust_status.status_entries[i].status = 0;
            
            if(local_trust_status.status_entries[i].status == 1){
              fprintf(stdout, "Node ID: "); hex_print(local_trust_status.status_entries[i].ak_digest, SHA256_DIGEST_LENGTH); fprintf(stdout, " --> T\n");
            }
            else{
              fprintf(stdout, "Node ID: "); hex_print(local_trust_status.status_entries[i].ak_digest, SHA256_DIGEST_LENGTH); fprintf(stdout, " --> NT\n");
              invalid_channels_attest[i] = 1;
            } 

            for(j = 0; j < TpaData[i].ima_log_blob.size; j++)
              free(TpaData[i].ima_log_blob.logEntry[j].template_data);
            free(TpaData[i].ima_log_blob.logEntry);
          }
        } else if(ret != WAM_NOT_FOUND) {
          fprintf(stdout, "Error while reading ret=%d\n", ret);        
        }
consensus:
        if(have_to_read == nodes_number + 1){ // +1 because have_to_read start count from 1
          // write "response" to heartbeat
          fprintf(stdout, "Sending local trust status results... \n");
          sendLocalTrustStatus(&ch_write_response, local_trust_status, nodes_number);
          // Get other RAs's local status to construct global trust status
          if(!readOthersTrustTables_Consensus(ch_read_status, nodes_number, local_trust_status, invalid_channels_status, &menuLock, verifier_status))
            goto end;
          for(j = 0; j < nodes_number; j++){
            verified_nodes[j] = 0;
            if(local_trust_status.status_entries[j].status == 0)
              local_trust_status.status_entries[j].status = -1;
          }
          have_to_read = 0;
        }
      } else {
        if(verified_nodes[i] == 0 && invalid_channels_attest[i] == 1){ 
          verified_nodes[i] = 1;
          have_to_read+=1;
          if(have_to_read == nodes_number + 1) goto consensus;
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
  free(ch_read_attest); free(ch_read_ak); free(ch_read_whitelist); free(ch_read_status);
  free(read_indexes); free(read_indexes_AkPub); free(read_indexes_whitelist); free(read_indexes_status);
  free(ak_files);
  free(offset); free(previous_msg_num);
  free(verified_nodes);
  free(local_trust_status.status_entries);
  free(invalid_channels_attest);
  free(invalid_channels_status);
  pthread_mutex_lock(&menuLock); // Lock a mutex for heartBeat_Status
  if(verifier_status == 0){ // stop
    fprintf(stdout, "Verifier Stopped\n");
    pthread_mutex_lock(&earlyLock);
    early_exit = 1;
    pthread_mutex_unlock(&earlyLock);
  }
  pthread_mutex_unlock(&menuLock); // Unlock a mutex for heartBeat_Status
  return ;
}