#include "common.h"

void init_IRdata(IRdata_ctx *ctx, int nodes_number) {
  ctx->TpaData = malloc(nodes_number * sizeof(TO_SEND));
  ctx->ver_response = malloc(nodes_number * sizeof(VERIFICATION_RESPONSE));
  ctx->ak_table = malloc(nodes_number * sizeof(AK_FILE_TABLE));
  ctx->whitelist_table = malloc(nodes_number * sizeof(WHITELIST_TABLE));
  ctx->pcrs_mem = malloc(nodes_number * sizeof(PCRS_MEM));
  ctx->local_trust_status.status_entries = malloc(nodes_number * sizeof(STATUS_ENTRY)); 

  for(int i = 0; i < nodes_number; i++){
    ctx->pcrs_mem[i].pcr10_sha1 = calloc((SHA_DIGEST_LENGTH + 1), sizeof(unsigned char));
    ctx->pcrs_mem[i].pcr10_sha256 = calloc((SHA256_DIGEST_LENGTH + 1), sizeof(unsigned char));
  }
  ctx->pcr9_sha1 = malloc((SHA_DIGEST_LENGTH + 1) * sizeof(unsigned char));
  ctx->pcr9_sha256 = malloc((SHA256_DIGEST_LENGTH + 1) * sizeof(unsigned char));
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
    int *verifier_status = ((ARGS_MENU *)in)->verifier_status;
    pthread_mutex_t *menuLock = ((ARGS_MENU *)in)->menuLock;
    char input[10];
    do {
      fprintf(stdout, "Press [1] --> Stop Verifier\n");
      my_gets_avoid_bufferoverflow(input, 10);
      if(atoi(input) == 1){
        pthread_mutex_lock(menuLock); // Lock a mutex for heartBeat_Status
        fprintf(stdout, "Waiting to process the last data. Gracefully stopping the Verifier!\n");
        *verifier_status = 1;
        pthread_mutex_unlock(menuLock); // Unlock a mutex for heartBeat_Status
      }
    }while(atoi(input) != 1);
    return;
}

bool legal_int(const char *str) {
    while (*str)
        if (!isdigit(*str++))
            return false;
    return true;
}

int computeDigestEVP(unsigned char* akPub, const char* sha_alg, unsigned char *digest){
  EVP_MD_CTX*mdctx;
  const EVP_MD *md;
  unsigned int md_len, i;
  unsigned char md_value[EVP_MAX_MD_SIZE];

  OpenSSL_add_all_digests();

  md = EVP_get_digestbyname(sha_alg);
  if (md == NULL) {
    printf("Unknown message digest %s\n", sha_alg);
    return false;
  }

  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, akPub, strlen(akPub));
  EVP_DigestFinal_ex(mdctx, digest, &md_len);
  EVP_MD_CTX_free(mdctx);

  return md_len;
}

u_int8_t* get_ak_file_path(AK_FILE_TABLE *ak_table, TO_SEND TpaData, int nodes_number) {
  int i;
  for(i = 0; i < nodes_number; i++) {
    if(!memcmp(ak_table[i].ak_md, TpaData.ak_digest_blob.buffer, TpaData.ak_digest_blob.size))
      return ak_table[i].path_name;
  }
  return NULL;
}

void get_Index_from_file(FILE *index_file, IOTA_Index *heartBeat_index, IOTA_Index *write_index, IOTA_Index *read_indexes, 
    IOTA_Index *read_indexes_AkPub, IOTA_Index *read_indexes_whitelist, IOTA_Index *read_indexes_status, int nodes_number) {
  int len_file, i = 0;
  char *data = NULL, read_index_base_str[20] = "read_index_", akread_index_base_str[20] = "AkPub_read_";
  char akpub_index_base_str[20]="pub_key_", index_AkPub_base_str[25]="AkPub_read_pubkey_";
  char whitelist_index_base_str[30]="whitelist_read_", whitelist_index_read_base_str[40]="whitelist_read_pubkey_";
  char base_index_str_status[30] = "status_read_", base_pub_str_status[40] = "status_read_pubkey_";

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
  for(i = 0; i < nodes_number; i++){
    base_index_str_status[12] = (i + 1) + '0';
    base_pub_str_status[19] = (i + 1) + '0';
    hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, base_index_str_status)->valuestring, INDEX_HEX_SIZE, read_indexes_status[i].index, INDEX_SIZE);
    hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, base_pub_str_status)->valuestring, (ED_PUBLIC_KEY_BYTES * 2) + 1, read_indexes_status[i].keys.pub, ED_PUBLIC_KEY_BYTES);
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

void sendLocalTrustStatus(WAM_channel *ch_send, STATUS_TABLE local_trust_status, int nodes_number) {
  size_t acc = 0, bytes_to_send = 0;
  int i, j;
  uint16_t valid_entries = 0;
  uint8_t last[4] = "done", *response_buff = NULL;

  bytes_to_send += sizeof(uint16_t);
  bytes_to_send += SHA256_DIGEST_LENGTH * sizeof(uint8_t);
  for(i = 0; i < nodes_number; i++) {
    if(local_trust_status.status_entries[i].status != -1){
      valid_entries+=1;
      bytes_to_send += (SHA256_DIGEST_LENGTH * sizeof(uint8_t)) + sizeof(int8_t);
    }
  }
  bytes_to_send += sizeof last;

  response_buff = malloc(sizeof(uint8_t) * bytes_to_send);
  if(response_buff == NULL){
    fprintf(stdout, "OOM\n");
    return ;
  }

  memcpy(response_buff + acc, &valid_entries, sizeof(uint16_t));
  acc += sizeof(uint16_t);
  memcpy(response_buff + acc, &local_trust_status.from_ak_digest, SHA256_DIGEST_LENGTH * sizeof(uint8_t));
  acc += SHA256_DIGEST_LENGTH * sizeof(uint8_t);
  for(i = 0; i < nodes_number; i++){
    if(local_trust_status.status_entries[i].status != -1){
      memcpy(response_buff + acc, &local_trust_status.status_entries[i].ak_digest, SHA256_DIGEST_LENGTH * sizeof(uint8_t));
      acc += SHA256_DIGEST_LENGTH * sizeof(uint8_t);
      memcpy(response_buff + acc, &local_trust_status.status_entries[i].status, sizeof(int8_t));
      acc += sizeof(int8_t);
    }
  }
  memcpy(response_buff + acc, last, sizeof last);
  acc += sizeof last;

  fprintf(stdout, "Writing at "); hex_print(ch_send->current_index.index, INDEX_SIZE);
  WAM_write(ch_send, response_buff, (uint32_t)bytes_to_send, false);
  fprintf(stdout, " --> DONE WRITING - Sent bytes = %d\n", bytes_to_send);
  
  free(response_buff);
}

bool get_my_ak_digest(uint8_t *my_ak_digest) {
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
  memcpy(my_ak_digest, digest, md_len);
  my_ak_digest[md_len] = '\0';
  return true;
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

int readOthersTrustTables_Consensus(WAM_channel *ch_read_status, int nodes_number, STATUS_TABLE local_trust_status, int *invalid_channels_status, pthread_mutex_t *menuLock, volatile int verifier_status) {
  uint32_t expected_response_size = DATA_SIZE, previous_msg_num[nodes_number], offset[nodes_number];
  uint8_t **read_response_messages, expected_response_messages[DATA_SIZE], last[4]="done";
  uint16_t max_number_trust_entries = 0;
  int i=0, j, acc = 0, invalid_table_index, *already_read, valid_local_entries = 0, ret = 1, *read_prints, ret_read = 0;
  STATUS_TABLE *read_local_trust_status, global_trust_status;

  already_read = calloc(nodes_number, sizeof(int));
  read_prints = calloc(nodes_number, sizeof(int));
  read_response_messages = (uint8_t**) malloc(nodes_number * sizeof(uint8_t *));
  for(i = 0; i < nodes_number; i++)
    read_response_messages[i] = (uint8_t *) malloc(DATA_SIZE * 2 * sizeof(uint8_t));
  
  read_local_trust_status = malloc((nodes_number + 1) * sizeof(STATUS_TABLE)); // plus my self. Later merge my local with those read from tangle
  
  for(i = 0; i < nodes_number; i++){
      ch_read_status[i].recv_bytes = 0;
      ch_read_status[i].recv_msg = 0;
      offset[i] = 0;
      previous_msg_num[i] = 0;
  }
  for(i = 0; i < nodes_number + 1; i++)
    read_local_trust_status[i].status_entries = NULL;
  global_trust_status.status_entries = NULL;

  i = 0;
  while(i != nodes_number) {
    if(invalid_channels_status[i] == 0 && already_read[i] == 0){
      if(read_prints[i] == 0) {
        fprintf(stdout, "Reading at "); hex_print(ch_read_status[i].read_idx, INDEX_SIZE); fprintf(stdout, "\n");
        read_prints[i] = 1;
      }
      ret_read = WAM_read(&ch_read_status[i], expected_response_messages, &expected_response_size);
      if(!ret_read){
        if(ch_read_status[i].recv_msg != previous_msg_num[i]){
          memcpy(read_response_messages[i] + offset[i], expected_response_messages, DATA_SIZE*sizeof(uint8_t));
          offset[i] += DATA_SIZE;
          previous_msg_num[i] += 1;
        }
        if(memcmp(last, read_response_messages[i] + ch_read_status[i].recv_bytes - sizeof last, sizeof last) == 0) {
          parseLocalTrustStatusMessage(read_response_messages[i], read_local_trust_status, i);
          fprintf(stdout, "Read status [%d] from ", ch_read_status[i].recv_bytes); hex_print(read_local_trust_status[i].from_ak_digest, 32); fprintf(stdout, "\n");
          if(read_local_trust_status[i].number_of_entries > max_number_trust_entries)
              max_number_trust_entries = read_local_trust_status[i].number_of_entries;
          already_read[i] = 1;
          i+=1;
        }
        pthread_mutex_lock(menuLock); // Lock a mutex for heartBeat_Status
        if(verifier_status == 1){ // stop
          pthread_mutex_unlock(menuLock); // Unlock a mutex for heartBeat_Status
          goto exit;
        }
        pthread_mutex_unlock(menuLock); // Unlock a mutex for heartBeat_Status
      } else if(ret_read != WAM_NOT_FOUND) {
        fprintf(stdout, "Error while reading ret=%d\n", ret_read);
      }
    } else {
      if(invalid_channels_status[i] == 1 && already_read[i] == 0){
        already_read[i] = 1;
        read_local_trust_status[i].status_entries = NULL;
        i+=1;
      }
    }
  }

  for(i = 0; i < local_trust_status.number_of_entries; i++)
    if(local_trust_status.status_entries[i].status != -1)
      valid_local_entries+=1;
  if(valid_local_entries > max_number_trust_entries)
    max_number_trust_entries = valid_local_entries;

  read_local_trust_status[nodes_number].number_of_entries = valid_local_entries;
  memcpy(read_local_trust_status[nodes_number].from_ak_digest, local_trust_status.from_ak_digest, SHA256_DIGEST_LENGTH * sizeof(uint8_t));
  read_local_trust_status[nodes_number].from_ak_digest[SHA256_DIGEST_LENGTH] = '\0';
  read_local_trust_status[nodes_number].status_entries = malloc(valid_local_entries * sizeof(STATUS_ENTRY));
  j = 0;
  for(i = 0; i < local_trust_status.number_of_entries; i++){
    if(local_trust_status.status_entries[i].status != -1){
      read_local_trust_status[nodes_number].status_entries[j].status = local_trust_status.status_entries[i].status;
      memcpy(read_local_trust_status[nodes_number].status_entries[j].ak_digest, local_trust_status.status_entries[i].ak_digest, SHA256_DIGEST_LENGTH * sizeof(uint8_t));
      read_local_trust_status[nodes_number].status_entries[j].ak_digest[SHA256_DIGEST_LENGTH] = '\0';
      j+=1;
    } 
  }

  /*fprintf(stdout, "RESULT: \n");
  for(i = 0; i < nodes_number + 1; i++) {
    if(read_local_trust_status[i].status_entries != NULL){
      fprintf(stdout, "From: "); hex_print(read_local_trust_status[i].from_ak_digest, 32); fprintf(stdout, "\n");
      for(j = 0; j < read_local_trust_status[i].number_of_entries; j++) {
        fprintf(stdout, "\tNode ID: "); hex_print(read_local_trust_status[i].status_entries[j].ak_digest, 32);
        fprintf(stdout, " status %d\n", read_local_trust_status[i].status_entries[j].status);
      }
    } else fprintf(stdout, "NULL\n");
  }*/

  global_trust_status.number_of_entries = max_number_trust_entries + 1;
  global_trust_status.status_entries = malloc(global_trust_status.number_of_entries * sizeof(STATUS_ENTRY));
  for(j = 0; j < global_trust_status.number_of_entries; j++)
    global_trust_status.status_entries[j].status = 0;
  ret = consensous_proc(read_local_trust_status, &global_trust_status, nodes_number + 1);
  if(ret == 0)
    goto exit;
  fprintf(stdout, "Consensous result: \n");
  for(j = 0; j < global_trust_status.number_of_entries; j++){
      if(global_trust_status.status_entries[j].status == 1) {
          fprintf(stdout, "Node ID: "); hex_print(global_trust_status.status_entries[j].ak_digest, SHA256_DIGEST_LENGTH); fprintf(stdout, " --> T\n");
      } else{
          fprintf(stdout, "Node ID: "); hex_print(global_trust_status.status_entries[j].ak_digest, SHA256_DIGEST_LENGTH); fprintf(stdout, " --> NT\n");
          invalid_table_index = checkNT_in_froms(global_trust_status.status_entries[j].ak_digest, read_local_trust_status, nodes_number);
          if(invalid_table_index >= 0 && invalid_table_index < nodes_number){
            invalid_channels_status[invalid_table_index] = 1;
          }
      }
  }
  fprintf(stdout, "\n");

exit:
  free(already_read); free(read_prints);
  for(i = 0; i < nodes_number; i++)
    free(read_response_messages[i]);
  free(read_response_messages);
  for(i = 0; i < nodes_number + 1; i++)
    if(read_local_trust_status[i].status_entries != NULL) free(read_local_trust_status[i].status_entries);
  free(read_local_trust_status);
  if(global_trust_status.status_entries != NULL) free(global_trust_status.status_entries);
  return ret;
}