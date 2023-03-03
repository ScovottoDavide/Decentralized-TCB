#include "all_util.h"
#include "tpm2_createek.h"
#include "tpm2_createak.h"
#include "tpm2_quote.h"
#include "PCR9Extend.h"

#define BILLION  1000000000L;

bool initialize_tpm(uint16_t *ek_handle, uint16_t *ak_handle);
int tpm2_getCap_handles_persistent(ESYS_CONTEXT *esys_context, uint16_t *ek_handle, uint16_t *ak_handle);
bool loadWhitelist(FILE *fp, struct whitelist_entry *white_entries, int size);
bool sendWhitelist_WAM(WAM_channel *ch_send_whitelist);
bool sendAkPub_WAM(WAM_channel *ch_send_AkPub, TO_SEND *TpaData);
int sendDataToRA_WAM(TO_SEND TpaData, ssize_t *imaLogBytesSize, WAM_channel *ch_send);
bool send_AK_Whitelist_WAM(WAM_channel *ch_send, TO_SEND *TpaData);
bool pcr_check_if_zeros(ESYS_CONTEXT *esys_context);
void get_Index_from_file(FILE *index_file, IOTA_Index *heartBeat_index, IOTA_Index *write_index, IOTA_Index *write_index_AkPub,
  IOTA_Index *write_index_whitelist);
void hex_print(uint8_t *raw_data, size_t raw_size);

int my_gets_avoid_bufferoverflow(char *buffer, size_t buffer_len);
void PoC_TPA(void *input);
void PoC_TPA_init(void *input);
void menu(void *in);

volatile int tpa_status = 0; // 0 -> do not stop; 1 --> stop the process
pthread_mutex_t menuLock;

enum { NS_PER_SECOND = 1000000000 };

void sub_timespec(struct timespec t1, struct timespec t2, struct timespec *td) {
    td->tv_nsec = t2.tv_nsec - t1.tv_nsec;
    td->tv_sec  = t2.tv_sec - t1.tv_sec;
    if (td->tv_sec > 0 && td->tv_nsec < 0)
    {
        td->tv_nsec += NS_PER_SECOND;
        td->tv_sec--;
    }
    else if (td->tv_sec < 0 && td->tv_nsec > 0)
    {
        td->tv_nsec -= NS_PER_SECOND;
        td->tv_sec++;
    }
}

int main(int argc, char *argv[]) {
  pthread_t th_tpa, th_menu, th_tpa_init;

  if(argc == 2) {
    if(strcmp("--help", argv[1]) == 0){
      fprintf(stdout, "Supported commands:\n");
      fprintf(stdout, "1. init --> Initialize TPM configuration: sudo ./PoC_TPA [path where 'index' file is] init\n");
      fprintf(stdout, "1. run --> Execute the Trusted Platform Agent: sudo ./PoC_TPA [path where 'index' file is] run\n");
      goto exit;
    } else if(strcmp("init", argv[1]) == 0){
      pthread_create(&th_tpa_init, NULL, (void *)&PoC_TPA_init, NULL);    
      pthread_join(th_tpa_init, NULL);
      goto exit;
    } else {
      fprintf(stdout, "For help --> ./PoC_TPA --help\n");
      goto exit;
    }
  }

  if(argc == 3) {
    if(strcmp("run", argv[2]) == 0) {
      pthread_create(&th_tpa, NULL, (void *)&PoC_TPA, (void *) argv[1]);
      pthread_create(&th_menu, NULL, (void *)&menu, NULL);

      pthread_join(th_tpa, NULL);
      pthread_join(th_menu, NULL);
      goto exit;
    }
    else {
      fprintf(stdout, "Unknown command!\n");
      fprintf(stdout, "For help --> ./PoC_TPA --help\n");
    }
  }

  if(argc > 3 || argc < 2) {
    fprintf(stdout, "Wrong usage!\n");
    fprintf(stdout, "For help --> ./PoC_TPA --help\n");
  }

exit:
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
    do{
      fprintf(stdout, "Press [1] --> Stop TPA\n");
      my_gets_avoid_bufferoverflow(input, 10);
      if(atoi(input) == 1){
        pthread_mutex_lock(&menuLock); // Lock a mutex for heartBeat_Status
        fprintf(stdout, "Waiting to process the last data. Gracefully stopping the TPA!\n");
        tpa_status = 1;
        pthread_mutex_unlock(&menuLock); // Unlock a mutex for heartBeat_Status
      }
    }while(atoi(input) != 1);
}

void PoC_TPA_init(void *input) {
  uint16_t ek_handle[HANDLE_SIZE], ak_handle[HANDLE_SIZE];

  if(!initialize_tpm(ek_handle, ak_handle)) {
    fprintf(stdout, "Could not initialize TPM conf\n");
    return ;
  }
  return ;
}

void PoC_TPA(void *input) {
  char *file_index_path_name = ((char *)input);
  struct timespec start, stop, delta;
  double accum;

  // TPM
  TSS2_RC tss_r;
  ESYS_CONTEXT *esys_context = NULL;
  TSS2_TCTI_CONTEXT *tcti_context = NULL;
  int persistent_handles = 0, i, ret = 0;
  TO_SEND TpaData;
  ssize_t imaLogBytesSize = 0;
  uint16_t ek_handle[HANDLE_SIZE], ak_handle[HANDLE_SIZE];

  // WAM
  uint8_t mykey[]="supersecretkeyforencryptionalby";
	WAM_channel ch_read_hearbeat, ch_send, ch_send_AkPub, ch_send_whitelist;
	WAM_AuthCtx a; a.type = AUTHS_NONE;
	WAM_Key k; k.data = mykey; k.data_len = (uint16_t) strlen((char*)mykey);
	uint8_t nonce[32];
	uint32_t expected_size = 32, fixed_nonce_size = 32;
	uint8_t  printed = 0;
  IOTA_Index heartBeat_index, write_index, write_index_AkPub, write_index_whitelist;
  FILE *index_file;

  if(!initialize_tpm(ek_handle, ak_handle)) {
    fprintf(stdout, "Could not initialize TPM conf\n");
    return ;
  }

	IOTA_Endpoint privatenet = {.hostname = "130.192.86.15\0",
							 .port = 14000,
							 .tls = false};

  index_file = fopen(file_index_path_name, "r");
  if(index_file == NULL){
    fprintf(stdout, "Cannot open file\n");
    return ;
  }
  get_Index_from_file(index_file, &heartBeat_index, &write_index, &write_index_AkPub, &write_index_whitelist);
  fclose(index_file);
	
  // set read index of heatbeat
  WAM_init_channel(&ch_read_hearbeat, 1, &privatenet, &k, &a);
	set_channel_index_read(&ch_read_hearbeat, heartBeat_index.index);
  // set write index for the AkPub
  WAM_init_channel(&ch_send_AkPub, 1, &privatenet, &k, &a);
  set_channel_index_write(&ch_send_AkPub, write_index_AkPub);
  // set write index for the whitelist
  WAM_init_channel(&ch_send_whitelist, 1, &privatenet, &k, &a);
  set_channel_index_write(&ch_send_whitelist, write_index_whitelist);
  // Set write index for the quote 
  WAM_init_channel(&ch_send, 1, &privatenet, &k, &a);
  set_channel_index_write(&ch_send, write_index);

  if(!sendAkPub_WAM(&ch_send_AkPub, &TpaData)) {
    fprintf(stdout, "Could not write AK pub on tangle\n");
    return ;
  }
  if(!sendWhitelist_WAM(&ch_send_whitelist)){
    fprintf(stdout, "Could not write Whitelist on tangle\n");
    return ;
  }

	while(1){
    if(!printed){
      fprintf(stdout, "Waiting nonce... \n");
      printed = 1;
    }
    //if(ch_read_hearbeat.recv_bytes > 32)
      //fprintf(stdout, "Entering read\n");
    ret = WAM_read(&ch_read_hearbeat, nonce, &fixed_nonce_size);
    //if(ch_read_hearbeat.recv_bytes > 32 && ret != WAM_NOT_FOUND)
      //fprintf(stdout, "Exited read, ret %d\n", ret);
    if(!ret){
      fprintf(stdout, "Nonce #%d\n", expected_size / 32);
      if(ch_read_hearbeat.recv_bytes == expected_size){
        expected_size+=fixed_nonce_size;
        printed = 0;

        TpaData.nonce_blob.tag = (u_int8_t)0;
        TpaData.nonce_blob.size = sizeof nonce;
        memcpy(TpaData.nonce_blob.buffer, nonce, TpaData.nonce_blob.size);
        
        tss_r = Tss2_TctiLdr_Initialize(NULL, &tcti_context);
        if (tss_r != TSS2_RC_SUCCESS) {
          printf("Could not initialize tcti context\n");
          return ;
        }
        tss_r = Esys_Initialize(&esys_context, tcti_context, NULL);
        if (tss_r != TSS2_RC_SUCCESS) {
          printf("Could not initialize esys context\n");
          return ;
        }
        if (pcr_check_if_zeros(esys_context)) {
          // Extend both
          ExtendPCR9(esys_context, "sha1");
          fprintf(stdout, "PCR9 sha1 extended\n");
          ExtendPCR9(esys_context, "sha256");
          fprintf(stdout, "PCR9 sha256 extended\n");
        }

        tss_r = tpm2_quote(esys_context, &TpaData, imaLogBytesSize, ak_handle);
        if (tss_r != TSS2_RC_SUCCESS) {
          printf("Error while computing quote!\n");
          return ;
        } 
        
        /** SEND DATA TO THE REMOTE ATTESTOR */
        fprintf(stdout, "Writing...\n");
        if( clock_gettime( CLOCK_REALTIME, &start) == -1 ) {
          perror( "clock gettime" );
          goto end;
        }
        sendDataToRA_WAM(TpaData, &imaLogBytesSize, &ch_send); 

        if( clock_gettime(CLOCK_REALTIME, &stop) == -1 ) {
          perror( "clock gettime" );
          goto end;
        }

        sub_timespec(start, stop, &delta);
        printf("TIME: %d.%.9ld\n", (int)delta.tv_sec, delta.tv_nsec);

        Esys_Finalize(&esys_context);
        Tss2_TctiLdr_Finalize (&tcti_context);

        pthread_mutex_lock(&menuLock); // Lock a mutex for heartBeat_Status
        if(tpa_status == 1){ // stop
          fprintf(stdout, "TPA Stopped\n");
          pthread_mutex_unlock(&menuLock); // Unlock a mutex for heartBeat_Status
          goto end;
        }
        pthread_mutex_unlock(&menuLock); // Unlock a mutex for heartBeat_Status
      }
    } else if(ret != WAM_NOT_FOUND){
      fprintf(stdout, "Error while reading ret=%d\n", ret);
    }
    pthread_mutex_lock(&menuLock); // Lock a mutex for heartBeat_Status
    if(tpa_status == 1){ // stop
      fprintf(stdout, "TPA Stopped\n");
      pthread_mutex_unlock(&menuLock); // Unlock a mutex for heartBeat_Status
      goto end;
    }
    pthread_mutex_unlock(&menuLock); // Unlock a mutex for heartBeat_Status
  }

end:
  free(TpaData.ak_digest_blob.buffer);
  /*for(i = 0; i < TpaData.ima_log_blob.size; i++)
    free(TpaData.ima_log_blob.logEntry[i].template_data);*/
  free(TpaData.ima_log_blob.logEntry);
  return ;
}

bool initialize_tpm(uint16_t *ek_handle, uint16_t *ak_handle) {
  FILE *keys_conf;
  // TPM
  TSS2_RC tss_r;
  ESYS_CONTEXT *esys_context = NULL;
  TSS2_TCTI_CONTEXT *tcti_context = NULL;
  int persistent_handles = 0, n, i;

  tss_r = Tss2_TctiLdr_Initialize(NULL, &tcti_context);
  if (tss_r != TSS2_RC_SUCCESS) {
    printf("Could not initialize tcti context\n");
    return false;
  }
  tss_r = Esys_Initialize(&esys_context, tcti_context, NULL);
  if (tss_r != TSS2_RC_SUCCESS) {
    printf("Could not initialize esys context\n");
    return false;
  }

  keys_conf = fopen("/etc/tc/keys.conf", "r");
  if(keys_conf == NULL) { // keys have not been created yet. Create EK and AK and save handle's index in file
    goto generate_keys;
  }else { // file exists: check that handles are written in the file. If not regenerate keys
    if(n = fread((char *)ek_handle, sizeof(char) * HANDLE_SIZE, 1, keys_conf) != 1){
      fprintf(stdout, "keys.conf file has been corrupted. Delete the file and re execute\n");
      goto error;
    }
    if(n = fread((char *)ak_handle, sizeof(char) * HANDLE_SIZE, 1, keys_conf) != 1){
      fprintf(stdout, "keys.conf file has been corrupted. Delete the file and re execute\n");
      goto error;
    }
    fclose(keys_conf);
    for(i = 0; i < HANDLE_SIZE; i++){
      if(ek_handle[i] == '\n') ek_handle[i] = '\0';
      if(ak_handle[i] == '\n') ak_handle[i] = '\0';
    } 
    
    // Read the # of persistent handles and check that created/existing handles really exist
    persistent_handles = tpm2_getCap_handles_persistent(esys_context, ek_handle, ak_handle);
    if (persistent_handles == -1) {
      printf("Error while reading persistent handles!\n");
      goto error;
    }
    if(persistent_handles == -2){
      fprintf(stdout, "Error, expected handles not found! keys.conf file has been corrupted. Delete the file and re execute\n");
      goto error;
    }
    goto exit;
  }

generate_keys:
  if(keys_conf != NULL) fclose(keys_conf);
  keys_conf = fopen("/etc/tc/keys.conf", "w");
  fprintf(stdout, "Generating EK...\n");
  tss_r = tpm2_createek(esys_context, ek_handle);
  if (tss_r != TSS2_RC_SUCCESS) {
    printf("Error in tpm2_createek\n");
    goto error;
  }
  fprintf(stdout, "Generating AK...\n");
  tss_r = tpm2_createak(esys_context, ek_handle, ak_handle);
  if (tss_r != TSS2_RC_SUCCESS) {
    printf("\tError creating AK\n");
    goto error;
  }
  //fprintf(keys_conf, "%s\n%s\n", ek_handle, ak_handle);
  fwrite(ek_handle, HANDLE_SIZE*sizeof(char), 1, keys_conf);
  fwrite(ak_handle, HANDLE_SIZE*sizeof(char), 1, keys_conf);
  fclose(keys_conf);
  goto exit;

error:
  Esys_Finalize(&esys_context);
  Tss2_TctiLdr_Finalize (&tcti_context);
  return false;

exit:
  Esys_Finalize(&esys_context);
  Tss2_TctiLdr_Finalize (&tcti_context);
  return true;
}

void get_Index_from_file(FILE *index_file, IOTA_Index *heartBeat_index, IOTA_Index *write_index, IOTA_Index *write_index_AkPub,
  IOTA_Index *write_index_whitelist) {
  int len_file;
  char *data = NULL;
   //get len of file
  fseek(index_file, 0, SEEK_END);
  len_file = ftell(index_file);
  fseek(index_file, 0, SEEK_SET);

   // read the data from the file 
  data = (char*) malloc(len_file + 1);
  fread(data, 1, len_file, index_file);
  data[len_file] = '\0';

  cJSON *json = cJSON_Parse(data);

  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "heartbeat")->valuestring, INDEX_HEX_SIZE, heartBeat_index->index, INDEX_SIZE);
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "heartBeat_pub_key")->valuestring, (ED_PUBLIC_KEY_BYTES * 2) + 1, heartBeat_index->keys.pub, ED_PUBLIC_KEY_BYTES);

  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "index")->valuestring, INDEX_HEX_SIZE, write_index->index, INDEX_SIZE);
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "pub_key")->valuestring, (ED_PUBLIC_KEY_BYTES * 2) + 1, write_index->keys.pub, ED_PUBLIC_KEY_BYTES);
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "priv_key")->valuestring, (ED_PRIVATE_KEY_BYTES * 2) + 1, write_index->keys.priv, ED_PRIVATE_KEY_BYTES);
  
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "AkPub_index")->valuestring, INDEX_HEX_SIZE, write_index_AkPub->index, INDEX_SIZE);
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "AkPub_pub_key")->valuestring, (ED_PUBLIC_KEY_BYTES * 2) + 1, write_index_AkPub->keys.pub, ED_PUBLIC_KEY_BYTES);
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "AkPub_priv_key")->valuestring, (ED_PRIVATE_KEY_BYTES * 2) + 1, write_index_AkPub->keys.priv, ED_PRIVATE_KEY_BYTES);
  
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "whitelist_index")->valuestring, INDEX_HEX_SIZE, write_index_whitelist->index, INDEX_SIZE);
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "whitelist_pub_key")->valuestring, (ED_PUBLIC_KEY_BYTES * 2) + 1, write_index_whitelist->keys.pub, ED_PUBLIC_KEY_BYTES);
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "whitelist_priv_key")->valuestring, (ED_PRIVATE_KEY_BYTES * 2) + 1, write_index_whitelist->keys.priv, ED_PRIVATE_KEY_BYTES);

  free(data);
}

bool sendAkPub_WAM(WAM_channel *ch_send_AkPub, TO_SEND *TpaData) {
  unsigned char *akPub = NULL;
  unsigned char *digest = NULL;

  bool res = openAKPub("/etc/tc/ak.pub.pem", &akPub);
  if(!res) {
    fprintf(stderr, "Could not read AK pub\n");
    return false;
  }

  digest = malloc((EVP_MAX_MD_SIZE)*sizeof(unsigned char));
  int md_len = computeDigestEVP(akPub, "sha256", digest);
  if(md_len <= 0)
    return false;
  TpaData->ak_digest_blob.tag = 3;
  TpaData->ak_digest_blob.size = md_len;
  TpaData->ak_digest_blob.buffer = malloc(TpaData->ak_digest_blob.size + 1 * sizeof(u_int8_t));
  memcpy(TpaData->ak_digest_blob.buffer, digest, TpaData->ak_digest_blob.size);
  TpaData->ak_digest_blob.buffer[TpaData->ak_digest_blob.size] = '\0';
  
  fprintf(stdout, "Writing AkPub...\n");
  WAM_write(ch_send_AkPub, akPub, (uint32_t)strlen(akPub), false);

  free(digest);
  return true;
}

bool loadWhitelist(FILE *fp, struct whitelist_entry *white_entries, int size) {
  unsigned char digest[SHA256_DIGEST_LENGTH*2 + 1];
  int file_path_len = 0;
  int i = 0;
  for (i = 0; i < size; i++) {
    fscanf(fp, "%s %d", white_entries[i].digest, &file_path_len);
    white_entries[i].path_len = file_path_len;
    white_entries[i].digest[SHA256_DIGEST_LENGTH*2] = '\0';
    white_entries[i].path = malloc(file_path_len + 1 * sizeof(char));
    fscanf(fp, "%s", white_entries[i].path);
    white_entries[i].path[file_path_len] = '\0';
    //fprintf(stdout, "%s %s\n", white_entries[i].digest, white_entries[i].path);
  }
  return true;
}

bool sendWhitelist_WAM(WAM_channel *ch_send_whitelist) {
  unsigned char *akPub = NULL;
  unsigned char *digest = NULL;
  uint8_t *to_send_data = NULL, last[4] = "done";
  size_t bytes_to_send = 0, acc = 0;
  FILE *whitelist_fp;
  int num_entries = 0, i;
  WHITELIST_BLOB whitelistBlob;

  bool res = openAKPub("/etc/tc/ak.pub.pem", &akPub);
  if(!res) {
    fprintf(stderr, "Could not read AK pub\n");
    return false;
  }
  digest = malloc((EVP_MAX_MD_SIZE)*sizeof(unsigned char));
  int md_len = computeDigestEVP(akPub, "sha256", digest);
  if(md_len <= 0)
    return false;
  memcpy(whitelistBlob.ak_digest, digest, md_len);
  whitelistBlob.ak_digest[SHA256_DIGEST_LENGTH] = '\0';

  whitelist_fp = fopen("../Whitelist_generator/whitelist", "rb");
  if (!whitelist_fp) {
    fprintf(stdout, "\nNo whitelist file found! Skipping whitelist verification!\n\n");
  } else {
    fscanf(whitelist_fp, "%d", &num_entries);
    whitelistBlob.number_of_entries = num_entries;
    whitelistBlob.white_entries = malloc(num_entries * sizeof(struct whitelist_entry));
    if (!whitelistBlob.white_entries) {
      fprintf(stdout, "OOM %d\n", num_entries);
      return false;
    }
    loadWhitelist(whitelist_fp, whitelistBlob.white_entries, num_entries);
    fclose(whitelist_fp);
  }

  bytes_to_send += SHA256_DIGEST_LENGTH * sizeof(u_int8_t);
  bytes_to_send += sizeof(u_int16_t);
  for(i = 0; i < whitelistBlob.number_of_entries; i++){
    bytes_to_send += SHA256_DIGEST_LENGTH*2 * sizeof(u_int8_t);
    bytes_to_send += sizeof(u_int16_t);
    bytes_to_send += whitelistBlob.white_entries[i].path_len * sizeof(u_int8_t);
  }
  bytes_to_send += sizeof last;

  to_send_data = malloc(bytes_to_send * sizeof(u_int8_t));

  memcpy(to_send_data + acc, whitelistBlob.ak_digest, SHA256_DIGEST_LENGTH * sizeof(u_int8_t));
  acc += SHA256_DIGEST_LENGTH * sizeof(u_int8_t);
  memcpy(to_send_data + acc, &whitelistBlob.number_of_entries, sizeof(u_int16_t));
  acc += sizeof(u_int16_t);
  for(i = 0; i < whitelistBlob.number_of_entries; i++){
    memcpy(to_send_data + acc, whitelistBlob.white_entries[i].digest, SHA256_DIGEST_LENGTH*2 * sizeof(u_int8_t));
    acc += SHA256_DIGEST_LENGTH*2 * sizeof(u_int8_t);
    memcpy(to_send_data + acc, &whitelistBlob.white_entries[i].path_len, sizeof(u_int16_t));
    acc += sizeof(u_int16_t);
    memcpy(to_send_data + acc, whitelistBlob.white_entries[i].path, whitelistBlob.white_entries[i].path_len * sizeof(u_int8_t));
    acc += whitelistBlob.white_entries[i].path_len * sizeof(u_int8_t);
  }
  memcpy(to_send_data + acc, last, sizeof last);
  acc += sizeof last;

  fprintf(stdout, "Writing Whitelist... [%d bytes] at: ", bytes_to_send); hex_print(ch_send_whitelist->current_index.index, INDEX_SIZE);
  WAM_write(ch_send_whitelist, to_send_data, (uint32_t)bytes_to_send, false);
  fprintf(stdout, "DONE\n", bytes_to_send);

  free(digest); 
  free(to_send_data);
  for(i = 0; i < whitelistBlob.number_of_entries; i++)
    free(whitelistBlob.white_entries[i].path);
  free(whitelistBlob.white_entries);
  return true;
}

bool send_AK_Whitelist_WAM(WAM_channel *ch_send, TO_SEND *TpaData) {
  unsigned char *akPub = NULL;
  unsigned char *digest = NULL;
  WHITELIST_BLOB whitelistBlob;
  uint8_t *to_send_data = NULL, last[4] = "done";
  size_t bytes_to_send = 0, acc = 0;
  int num_entries = 0, i;

  bool res = openAKPub("/etc/tc/ak.pub.pem", &akPub);
  if(!res) {
    fprintf(stderr, "Could not read AK pub\n");
    return false;
  }

  digest = malloc((EVP_MAX_MD_SIZE)*sizeof(unsigned char));
  int md_len = computeDigestEVP(akPub, "sha256", digest);
  if(md_len <= 0)
    return false;
  TpaData->ak_digest_blob.tag = 3;
  TpaData->ak_digest_blob.size = md_len;
  TpaData->ak_digest_blob.buffer = malloc(TpaData->ak_digest_blob.size + 1 * sizeof(u_int8_t));
  memcpy(TpaData->ak_digest_blob.buffer, digest, TpaData->ak_digest_blob.size);
  TpaData->ak_digest_blob.buffer[TpaData->ak_digest_blob.size] = '\0';
  memcpy(whitelistBlob.ak_digest, digest, md_len);
  whitelistBlob.ak_digest[SHA256_DIGEST_LENGTH] = '\0';
   
  FILE* whitelist_fp = fopen("../Whitelist_generator/whitelist", "rb");
  if (!whitelist_fp) {
    fprintf(stdout, "\nNo whitelist file found! Skipping whitelist verification!\n\n");
  } else {
    fscanf(whitelist_fp, "%d", &num_entries);
    whitelistBlob.number_of_entries = num_entries;
    whitelistBlob.white_entries = malloc(num_entries * sizeof(struct whitelist_entry));
    if (!whitelistBlob.white_entries) {
      fprintf(stdout, "OOM %d\n", num_entries);
      return false;
    }
    loadWhitelist(whitelist_fp, whitelistBlob.white_entries, num_entries);
    fclose(whitelist_fp);
  }

  /*WHITELIST_BLOB SIZE*/
  bytes_to_send += SHA256_DIGEST_LENGTH * sizeof(u_int8_t);
  bytes_to_send += sizeof(u_int16_t);
  for(i = 0; i < whitelistBlob.number_of_entries; i++){
    bytes_to_send += SHA256_DIGEST_LENGTH*2 * sizeof(u_int8_t);
    bytes_to_send += sizeof(u_int16_t);
    bytes_to_send += whitelistBlob.white_entries[i].path_len * sizeof(u_int8_t);
  }
  /*AK_DIGEST SIZE*/
  bytes_to_send += strlen(akPub); 
  bytes_to_send += sizeof last;

  to_send_data = malloc(bytes_to_send * sizeof(u_int8_t));

  memcpy(to_send_data + acc, whitelistBlob.ak_digest, SHA256_DIGEST_LENGTH * sizeof(u_int8_t));
  acc += SHA256_DIGEST_LENGTH * sizeof(u_int8_t);
  memcpy(to_send_data + acc, &whitelistBlob.number_of_entries, sizeof(u_int16_t));
  acc += sizeof(u_int16_t);
  for(i = 0; i < whitelistBlob.number_of_entries; i++){
    memcpy(to_send_data + acc, whitelistBlob.white_entries[i].digest, SHA256_DIGEST_LENGTH*2 * sizeof(u_int8_t));
    acc += SHA256_DIGEST_LENGTH*2 * sizeof(u_int8_t);
    memcpy(to_send_data + acc, &whitelistBlob.white_entries[i].path_len, sizeof(u_int16_t));
    acc += sizeof(u_int16_t);
    memcpy(to_send_data + acc, whitelistBlob.white_entries[i].path, whitelistBlob.white_entries[i].path_len * sizeof(u_int8_t));
    acc += whitelistBlob.white_entries[i].path_len * sizeof(u_int8_t);
  }
  /*AK_DIGEST ONLY*/
  memcpy(to_send_data + acc, akPub, strlen(akPub) * sizeof(unsigned char));

  memcpy(to_send_data + acc, last, sizeof last);
  acc += sizeof last;
  

  free(digest);
  free(to_send_data);
  for(i = 0; i < whitelistBlob.number_of_entries; i++)
    free(whitelistBlob.white_entries[i].path);
  free(whitelistBlob.white_entries);
}

int tpm2_getCap_handles_persistent(ESYS_CONTEXT *esys_context, uint16_t *ek_handle, uint16_t *ak_handle) {
  TSS2_RC tss_r;
  TPM2_CAP capability = TPM2_CAP_HANDLES;
  UINT32 property = TPM2_HR_PERSISTENT;
  UINT32 propertyCount = TPM2_MAX_CAP_HANDLES;
  TPMS_CAPABILITY_DATA *capabilityData;
  TPMI_YES_NO moreData;
  char handle_hex[HANDLE_SIZE];
  int h1 = 0, h2 = 0;

  //printf("\nReading persistent handles!\n");
  tss_r = Esys_GetCapability(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
    ESYS_TR_NONE, capability, property,
    propertyCount, &moreData, &capabilityData);
    if (tss_r != TSS2_RC_SUCCESS) {
      printf("Error while reading persistent handles\n");
      return -1;
    }
    int i = 0;
    //printf("Persistent handles present in NVRAM are %d\n", capabilityData->data.handles.count);
    /*for (i = 0; i < capabilityData->data.handles.count; i++) {
      printf("Persistent Handle: 0x%X\n", capabilityData->data.handles.handle[i]);
    }*/
    for (i = 0; i < capabilityData->data.handles.count; i++) {
      snprintf(handle_hex, HANDLE_SIZE, "0x%X", capabilityData->data.handles.handle[i]);
      if(strcmp((char *)ek_handle, handle_hex) == 0) h1 = 1;
      if(strcmp((char *)ak_handle, handle_hex) == 0) h2 = 1;
    }
    if(h1 && h2)
      return 0;
    return -2;
}

int sendDataToRA_WAM(TO_SEND TpaData, ssize_t *imaLogBytesSize, WAM_channel *ch_send) {
  uint8_t *to_send_data = NULL;
  size_t bytes_to_send = 0, acc = 0;
  int i = 0;
  uint8_t last[4] = "done";

  // sig
  bytes_to_send += sizeof(u_int8_t) + sizeof(u_int16_t) + (sizeof(u_int8_t) * TpaData.sig_blob.size);
  // message
  bytes_to_send += sizeof(u_int8_t) + sizeof(u_int16_t) + (sizeof(u_int8_t) * TpaData.message_blob.size);
  // log
  bytes_to_send += sizeof(u_int8_t) + sizeof(u_int16_t) + sizeof(u_int8_t);
  for (i = 0; i < TpaData.ima_log_blob.size; i++) {
    // send header
    bytes_to_send += sizeof TpaData.ima_log_blob.logEntry[i].header;
    // send name
    bytes_to_send += TpaData.ima_log_blob.logEntry[i].header.name_len * sizeof(char);
    // send template data len
    bytes_to_send += sizeof(u_int32_t);
    // send template data;
    bytes_to_send += TpaData.ima_log_blob.logEntry[i].template_data_len * sizeof(u_int8_t);
  }
  // ak pub md
  bytes_to_send += sizeof(u_int8_t) + sizeof(u_int16_t) + (TpaData.ak_digest_blob.size * sizeof(u_int8_t));
  bytes_to_send += sizeof last;
  
  to_send_data = malloc(sizeof(u_int8_t) * bytes_to_send);
  if(to_send_data == NULL){
    fprintf(stdout, "OOM\n");
    return -1;
  }

  memcpy(to_send_data, &TpaData.sig_blob.tag, sizeof(u_int8_t));
  acc += sizeof(u_int8_t);
  memcpy(to_send_data + acc, &TpaData.sig_blob.size, sizeof(u_int16_t));
  acc += sizeof(u_int16_t);
  memcpy(to_send_data + acc, &TpaData.sig_blob.buffer, sizeof(u_int8_t) * TpaData.sig_blob.size);
  acc += sizeof(u_int8_t) * TpaData.sig_blob.size;

  memcpy(to_send_data + acc, &TpaData.message_blob.tag, sizeof(u_int8_t));
  acc += sizeof(u_int8_t);
  memcpy(to_send_data + acc, &TpaData.message_blob.size, sizeof(u_int16_t));
  acc += sizeof(u_int16_t);
  memcpy(to_send_data + acc, &TpaData.message_blob.buffer, sizeof(u_int8_t) * TpaData.message_blob.size);
  acc += sizeof(u_int8_t) * TpaData.message_blob.size;

  memcpy(to_send_data + acc, &TpaData.ima_log_blob.tag, sizeof(u_int8_t));
  acc += sizeof(u_int8_t);
  memcpy(to_send_data + acc, &TpaData.ima_log_blob.size, sizeof(u_int16_t));
  acc += sizeof(u_int16_t);
  memcpy(to_send_data + acc, &TpaData.ima_log_blob.wholeLog, sizeof(u_int8_t));
  acc += sizeof(u_int8_t);

  for (i = 0; i < TpaData.ima_log_blob.size; i++) {
    // send header
    memcpy(to_send_data + acc, &TpaData.ima_log_blob.logEntry[i].header, sizeof TpaData.ima_log_blob.logEntry[i].header);
    acc += sizeof TpaData.ima_log_blob.logEntry[i].header;
    *imaLogBytesSize += sizeof TpaData.ima_log_blob.logEntry[i].header;
    // send name
    memcpy(to_send_data + acc, &TpaData.ima_log_blob.logEntry[i].name, TpaData.ima_log_blob.logEntry[i].header.name_len * sizeof(char));
    acc += TpaData.ima_log_blob.logEntry[i].header.name_len * sizeof(char);
    *imaLogBytesSize += TpaData.ima_log_blob.logEntry[i].header.name_len * sizeof(char);
    // send template data len
    memcpy(to_send_data + acc, &TpaData.ima_log_blob.logEntry[i].template_data_len, sizeof(u_int32_t));
    acc += sizeof(u_int32_t);
    *imaLogBytesSize += sizeof(u_int32_t);
    // send template data
    memcpy(to_send_data + acc, &TpaData.ima_log_blob.logEntry[i].template_data, TpaData.ima_log_blob.logEntry[i].template_data_len * sizeof(u_int8_t));
    acc += TpaData.ima_log_blob.logEntry[i].template_data_len * sizeof(u_int8_t);
    *imaLogBytesSize += TpaData.ima_log_blob.logEntry[i].template_data_len * sizeof(u_int8_t);
  }

  memcpy(to_send_data + acc, &TpaData.ak_digest_blob.tag, sizeof(u_int8_t));
  acc += sizeof(u_int8_t);
  memcpy(to_send_data + acc, &TpaData.ak_digest_blob.size, sizeof(u_int16_t));
  acc += sizeof(u_int16_t);
  memcpy(to_send_data + acc, TpaData.ak_digest_blob.buffer, sizeof(u_int8_t) * TpaData.ak_digest_blob.size);
  acc += sizeof(u_int8_t) * TpaData.ak_digest_blob.size;

  memcpy(to_send_data + acc, last, sizeof last);
  acc += sizeof last;

  fprintf(stdout, "Writing at "); hex_print(ch_send->current_index.index, INDEX_SIZE); fprintf(stdout, "\n");
  WAM_write(ch_send, to_send_data, (uint32_t)bytes_to_send, false);
  fprintf(stdout, "DONE WRITING - Sent bytes = %d, ima = %d\n\n", bytes_to_send, *imaLogBytesSize);

  free(to_send_data);
}

bool pcr_check_if_zeros(ESYS_CONTEXT *esys_context) {
  UINT32 i;
  size_t vi = 0; /* value index */
  UINT32 di = 0; /* digest index */
  u_int8_t pcr_max[SHA256_DIGEST_LENGTH];
  TSS2_RC tss_r;

  memset(pcr_max, 0, SHA256_DIGEST_LENGTH); /* initial PCR9-sha256 (is the max) content 0..0 */

  // Prepare TPML_PCR_SELECTION to read only PCR9
  // If PCR9 (sha1+sha256) are already extended, do NOT extend them more otherwise it's not possible to check its integrity
  TPML_PCR_SELECTION pcr_select;
  tpm2_pcrs pcrs;
  bool res = pcr_parse_selections("sha1:9+sha256:9", &pcr_select);
  if (!res)
  return false;

  tss_r = pcr_read_pcr_values(esys_context, &pcr_select, &pcrs);
  if (tss_r != TSS2_RC_SUCCESS) {
    fprintf(stderr, "Error while reading PCRs from TPM\n");
    return false;
  }

  // Go through all PCRs in each bank
  for (i = 0; i < pcr_select.count; i++) {
    const char *alg_name;
    if (pcr_select.pcrSelections[i].hash == TPM2_ALG_SHA1) {
      alg_name = malloc(strlen("sha1") * sizeof(char));
      alg_name = "sha1";
    }
    else if (pcr_select.pcrSelections[i].hash == TPM2_ALG_SHA256) {
      alg_name = malloc(strlen("sha256") * sizeof(char));
      alg_name = "sha256";
    }

    // Go through all PCRs in this banks
    unsigned int pcr_id;
    for (pcr_id = 0; pcr_id < pcr_select.pcrSelections[i].sizeofSelect * 8u; pcr_id++) {
      // skip unset pcrs (bit = 0)
      if (!(pcr_select.pcrSelections[i].pcrSelect[((pcr_id) / 8)] & (1 << ((pcr_id) % 8)))){
        continue;
      }

      if (vi >= pcrs.count || di >= pcrs.pcr_values[vi].count) {
        fprintf(stderr, "Trying to print but nothing more! di: %d, count: %d\n", di, pcrs.pcr_values[vi].count);
        return false;
      }

      // Print current PRC content (digest value)
      TPM2B_DIGEST *d = &pcrs.pcr_values[vi].digests[di];
      if (pcr_select.pcrSelections[i].hash == TPM2_ALG_SHA1) {
        if (memcmp(d->buffer, pcr_max, SHA_DIGEST_LENGTH))
        return false;
      }
      else if (pcr_select.pcrSelections[i].hash == TPM2_ALG_SHA256) {
        if (memcmp(d->buffer, pcr_max, SHA256_DIGEST_LENGTH))
        return false;
      }

      if (++di >= pcrs.pcr_values[vi].count) {
        di = 0;
        ++vi;
      }
    }
  }

  return true;
}

void hex_print(uint8_t *raw_data, size_t raw_size) {
  int i;

  for(i = 0; i < raw_size; i++)
    fprintf(stdout, "%02X", raw_data[i]);
  fprintf(stdout, "\n");
}