#include "load_whitelists.h"
#include "read_akpub.h"
#include "whitelist_verify.h"
#include "tpm2_checkquote.h"

void PoC_Verifier(void *input);

volatile int verifier_status = 0; // 0 -> do not stop; 1 --> stop the process
volatile int early_exit = 0;
pthread_mutex_t menuLock, earlyLock;

int main(int argc, char const *argv[]) {
  ARGS *args = malloc(sizeof(ARGS));
  ARGS_MENU *args_menu = malloc(sizeof(ARGS_MENU)); 
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

  args_menu->menuLock = &menuLock;
  args_menu->verifier_status = &verifier_status;

  pthread_create(&th_verifier, NULL, (void *)&PoC_Verifier, (void *) args);
  pthread_create(&th_menu, NULL, (void *)&menu, (void *) args_menu);

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

void PoC_Verifier(void *input){
  /* Convert thread args */
  int nodes_number = ((ARGS *)input)->nodes_number;
  const char *file_index_path_name = ((ARGS *)input)->index_file_path_name;
  /* ------------------- */
  int i, j, invalid_table_index, ret = 0, print_nonce = 0;
  uint8_t have_to_read = 0;

  /* WAM_Channel setup data definition */
  uint8_t mykey[]="supersecretkeyforencryptionalby";
	WAM_AuthCtx a; a.type = AUTHS_NONE;
	WAM_Key k; k.data = mykey; k.data_len = (uint16_t) strlen((char*)mykey);
  IOTA_Endpoint privatenet = {.hostname = "130.192.86.15\0",
							                .port = 14000,
							                .tls = false};
  /* --------------------------------- */
    
  IRdata_ctx IRdata_ctx;
  WAM_ctx WAM_ctx;
	support_ctx support_ctx;

  init_IRdata_ctx(&IRdata_ctx, nodes_number);
  WAM_ctx_alloc(&WAM_ctx, nodes_number, file_index_path_name);
  WAM_ctx_init_channels(&WAM_ctx, nodes_number, &privatenet, &k, &a);
  init_Support_ctx(&support_ctx, nodes_number);

  // First get all the AKs and construct table in order to recognize each TpaData received from the various Tpas
  cleanUpFolder("/etc/tc/TPA_AKs");
  srand((unsigned int)(time(NULL)));
  for(i = 0; i < nodes_number; i++){
    int res = read_and_save_AKs(&WAM_ctx.ch_read_ak[i], IRdata_ctx.ak_table, IRdata_ctx.ak_files[i], i, &verifier_status, menuLock);
    if(res < 0){
      fprintf(stdout, "Verifier Stopped while waiting for AK pubs of TPAs\n");
      goto early_end;
    }
  }
  fprintf(stdout, "AK map constructed\n");

  for(i = 0; i < nodes_number; i++){
    if(!read_and_save_whitelist(&WAM_ctx.ch_read_whitelist[i], IRdata_ctx.whitelist_table, i))
      goto early_end;
  }
  fprintf(stdout, "Whitelist map constructed\n");
  for(i = 0; i < nodes_number; i++)
    preparePCRSmap(IRdata_ctx.pcrs_mem, IRdata_ctx.ak_table, i);
  fprintf(stdout, "PCRS map constructed\n");

  fprintf(stdout, "\n Reading...\n");
  while(1){
    if(!print_nonce){
      fprintf(stdout, "Waiting nonce from "); hex_print(WAM_ctx.ch_read_hearbeat.read_idx, INDEX_SIZE); fprintf(stdout, "\n");
      print_nonce = 1;
    }
    ret = WAM_read(&WAM_ctx.ch_read_hearbeat, support_ctx.nonce, &support_ctx.fixed_nonce_size);
    if(!ret){
       if(WAM_ctx.ch_read_hearbeat.recv_bytes == support_ctx.expected_size && !have_to_read){
        fprintf(stdout, "Nonce received # %d\n", support_ctx.expected_size / 32);
        // new nonce arrived --> read new attestations
        support_ctx.expected_size+=support_ctx.fixed_nonce_size;
        have_to_read = 1;
        print_nonce = 0;

        for(i = 0; i < nodes_number; i++){
          WAM_ctx.ch_read_attest[i].recv_bytes = 0;
          WAM_ctx.ch_read_attest[i].recv_msg = 0;
          support_ctx.offset[i] = 0;
          support_ctx.previous_msg_num[i] = 0;
        }
        IRdata_ctx.nonce_blob.tag = (u_int8_t)0;
        IRdata_ctx.nonce_blob.size = sizeof support_ctx.nonce;
        memcpy(IRdata_ctx.nonce_blob.buffer, support_ctx.nonce, IRdata_ctx.nonce_blob.size);
      }
    } else if(ret != WAM_NOT_FOUND){
      fprintf(stdout, "Error while reading Nonce\n");
    }
    i = 0;
    while(have_to_read > 0){
      if(support_ctx.verified_nodes[i] == 0 && support_ctx.invalid_channels_attest[i] != 1){ 
        ret = WAM_read(&WAM_ctx.ch_read_attest[i], support_ctx.expected_attest_message, &support_ctx.expected_size_attest_message);
        if(!ret){           
          if(WAM_ctx.ch_read_attest[i].recv_msg != support_ctx.previous_msg_num[i]) {
            memcpy(support_ctx.read_attest_message[i] + support_ctx.offset[i], support_ctx.expected_attest_message, DATA_SIZE);
            support_ctx.offset[i] += DATA_SIZE;
            if(support_ctx.offset[i] > support_ctx.attest_messages_sizes[i]){
              support_ctx.attest_messages_sizes[i] += support_ctx.attest_messages_size_increment;
              support_ctx.read_attest_message[i] = realloc(support_ctx.read_attest_message[i], support_ctx.attest_messages_sizes[i] * sizeof(uint8_t));
            }
            support_ctx.previous_msg_num[i] += 1;
          } 
          if(memcmp(support_ctx.last, support_ctx.read_attest_message[i] + WAM_ctx.ch_read_attest[i].recv_bytes - sizeof support_ctx.last, sizeof support_ctx.last) == 0){
            if(WAM_ctx.ch_read_attest[i].recv_bytes < support_ctx.attest_messages_sizes[i]){
              support_ctx.attest_messages_sizes[i] = WAM_ctx.ch_read_attest[i].recv_bytes;
              support_ctx.read_attest_message[i] = realloc(support_ctx.read_attest_message[i], support_ctx.attest_messages_sizes[i] * sizeof(uint8_t));
            }
            parseTPAdata(IRdata_ctx.TpaData, support_ctx.read_attest_message[i], i);
            have_to_read += 1;

            if (!PCR9_calculation(IRdata_ctx.pcr9_sha1, IRdata_ctx.pcr9_sha256, IRdata_ctx.ak_table, IRdata_ctx.TpaData[i], nodes_number)) {
              fprintf(stderr, "PCR9 calculation failed\n");
              goto end;
            }

            // PCR10 calculation + whitelist verify
            int white_index = getIndexFromDigest(IRdata_ctx.TpaData[i].ak_digest_blob.buffer, IRdata_ctx.whitelist_table, nodes_number);
            if(white_index < 0){
              fprintf(stdout, "Error while retrieving correct whitelist from TPA Ak digest\n");
              goto end;
            }
            int pcrs_index = getIndexForPCR(IRdata_ctx.pcrs_mem, IRdata_ctx.TpaData[i].ak_digest_blob.buffer, nodes_number);
            if(pcrs_index < 0){
              fprintf(stdout, "Could not retrieve the correct old pcr");
              goto end;
            }
            memcpy(&IRdata_ctx.ver_response[i].ak_digest, IRdata_ctx.whitelist_table[white_index].ak_digest, SHA256_DIGEST_LENGTH);
            IRdata_ctx.ver_response[i].ak_digest[SHA256_DIGEST_LENGTH] = '\0';
            if(IRdata_ctx.TpaData[i].ima_log_blob.wholeLog == 1){ // If whole log is sent reset to 0 the pcrs otherwise checkquote will always fail after 1st round
              memset(IRdata_ctx.pcrs_mem[pcrs_index].pcr10_sha256, 0, SHA256_DIGEST_LENGTH);
              memset(IRdata_ctx.pcrs_mem[pcrs_index].pcr10_sha1, 0, SHA_DIGEST_LENGTH);
            }
            //fprintf(stdout, "Calculating PCR10s and performing whitelist checks...\n");
            if(!verify_PCR10_whitelist(IRdata_ctx.pcrs_mem[pcrs_index].pcr10_sha1, IRdata_ctx.pcrs_mem[pcrs_index].pcr10_sha256, IRdata_ctx.TpaData[i].ima_log_blob, &IRdata_ctx.ver_response[i], IRdata_ctx.whitelist_table[white_index])){
              fprintf(stdout, "Error while calculating pcr10s or verifying whitelist\n");
              goto end;
            }

            if(!tpm2_checkquote(IRdata_ctx.TpaData[i], IRdata_ctx.nonce_blob, IRdata_ctx.ak_table, nodes_number, IRdata_ctx.pcrs_mem[pcrs_index].pcr10_sha256, IRdata_ctx.pcrs_mem[pcrs_index].pcr10_sha1, IRdata_ctx.pcr9_sha256, IRdata_ctx.pcr9_sha1))
              IRdata_ctx.ver_response[i].is_quote_successful = 0;
            else IRdata_ctx.ver_response[i].is_quote_successful = 1; 

            support_ctx.verified_nodes[i] = 1;
            memcpy(IRdata_ctx.local_trust_status.status_entries[i].ak_digest, IRdata_ctx.TpaData[i].ak_digest_blob.buffer, SHA256_DIGEST_LENGTH * sizeof(uint8_t));
            IRdata_ctx.local_trust_status.status_entries[i].ak_digest[SHA256_DIGEST_LENGTH] = '\0';
            if(IRdata_ctx.ver_response[i].is_quote_successful == 1 && IRdata_ctx.ver_response[i].number_white_entries == 0)
              IRdata_ctx.local_trust_status.status_entries[i].status = 1;
            else IRdata_ctx.local_trust_status.status_entries[i].status = 0;
            
            if(IRdata_ctx.local_trust_status.status_entries[i].status == 1){
              fprintf(stdout, "Node ID: "); hex_print(IRdata_ctx.local_trust_status.status_entries[i].ak_digest, SHA256_DIGEST_LENGTH); fprintf(stdout, " --> T\n");
            }
            else{
              fprintf(stdout, "Node ID: "); hex_print(IRdata_ctx.local_trust_status.status_entries[i].ak_digest, SHA256_DIGEST_LENGTH); fprintf(stdout, " --> NT\n");
              support_ctx.invalid_channels_attest[i] = 1;
            } 

            for(j = 0; j < IRdata_ctx.TpaData[i].ima_log_blob.size; j++)
              free(IRdata_ctx.TpaData[i].ima_log_blob.logEntry[j].template_data);
            free(IRdata_ctx.TpaData[i].ima_log_blob.logEntry);
          }
        } else if(ret != WAM_NOT_FOUND) {
          fprintf(stdout, "Error while reading ret=%d\n", ret);        
        }
consensus:
        if(have_to_read == nodes_number + 1){ // +1 because have_to_read start count from 1
          // write "response" to heartbeat
          fprintf(stdout, "Sending local trust status results... \n");
          sendLocalTrustStatus(&WAM_ctx.ch_write_response, IRdata_ctx.local_trust_status, nodes_number);
          // Get other RAs's local status to construct global trust status
          if(!readOthersTrustTables_Consensus(WAM_ctx.ch_read_status, nodes_number, IRdata_ctx.local_trust_status, support_ctx.invalid_channels_status, &menuLock, verifier_status))
            goto end;
          for(j = 0; j < nodes_number; j++){
            support_ctx.verified_nodes[j] = 0;
            if(IRdata_ctx.local_trust_status.status_entries[j].status == 0)
              IRdata_ctx.local_trust_status.status_entries[j].status = -1;
          }
          have_to_read = 0;
        }
      } else {
        if(support_ctx.verified_nodes[i] == 0 && support_ctx.invalid_channels_attest[i] == 1){ 
          support_ctx.verified_nodes[i] = 1;
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
  freeLate_support_ctx(&support_ctx, nodes_number);
  freeLate_IRdata_ctx(&IRdata_ctx, nodes_number);

early_end:
  freeEarly_IRdata_ctx(&IRdata_ctx, nodes_number);
  free_WAM_ctx(&WAM_ctx);
  freeEarly_support_ctx(&support_ctx);
  
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