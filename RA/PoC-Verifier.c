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
      IOTA_Index *read_indexes, IOTA_Index *read_indexes_AkPub, int nodes_number);
void parseTPAdata(TO_SEND *TpaData, uint8_t *read_attest_message);
void sendRAresponse(WAM_channel *ch_send, VERIFICATION_RESPONSE ver_response);

int main(int argc, char const *argv[]) {
  int i, j, *attested_nodes;
  TO_SEND *TpaData; VERIFICATION_RESPONSE ver_response; AK_FILE_TABLE *ak_table; NONCE_BLOB nonce_blob;
  FILE *index_file, **ak_files;
  
  IOTA_Index heartBeat_index, *read_indexes = NULL, *read_indexes_AkPub = NULL, write_response_index;
  uint8_t mykey[]="supersecretkeyforencryptionalby";
	WAM_channel ch_read_hearbeat, *ch_read_attest, ch_write_response, *ch_read_ak;
	WAM_AuthCtx a; a.type = AUTHS_NONE;
	WAM_Key k; k.data = mykey; k.data_len = (uint16_t) strlen((char*)mykey);
	
  uint32_t expected_size = 32, expected_size_attest_message = DATA_SIZE, *offset;
	uint8_t ret = 0, **read_attest_message = NULL, expected_attest_message[DATA_SIZE], have_to_read = 0, nonce[32], last[4] = "done";
  uint16_t *previous_msg_num;

  unsigned char *pcr9_sha1 = NULL, *pcr9_sha256 = NULL, *pcr10_sha256 = NULL, *pcr10_sha1 = NULL;

  if(argc != 3){
    fprintf(stdout, "Please specify the file path and the number of nodes\n");
    return -1;
  }    
  if(atoi(argv[2]) < 0 || !legal_int(argv[2])){
    fprintf(stdout, "Entered parameter is NaN or it has to be greater than 0\n");
    return -1;
  }
  int nodes_number = atoi(argv[2]);

  TpaData = malloc(nodes_number * sizeof(TO_SEND));
  ch_read_attest = malloc(nodes_number * sizeof(WAM_channel));
  ch_read_ak = malloc(nodes_number * sizeof(WAM_channel));
  read_indexes = malloc(nodes_number * sizeof(IOTA_Index));
  read_indexes_AkPub = malloc(nodes_number * sizeof(IOTA_Index));
  ak_table = malloc(nodes_number * sizeof(AK_FILE_TABLE));
  ak_files = malloc(nodes_number * sizeof(FILE *));
  offset = malloc(nodes_number * sizeof(uint32_t));
  previous_msg_num = malloc(nodes_number * sizeof(uint16_t));

  pcr9_sha1 = malloc((SHA_DIGEST_LENGTH + 1) * sizeof(unsigned char));
  pcr10_sha1 = calloc((SHA_DIGEST_LENGTH + 1), sizeof(unsigned char));
  pcr9_sha256 = malloc((SHA256_DIGEST_LENGTH + 1) * sizeof(unsigned char));
  pcr10_sha256 = calloc((SHA256_DIGEST_LENGTH + 1), sizeof(unsigned char));

  IOTA_Endpoint privatenet = {.hostname = "130.192.86.15\0",
							 .port = 14265,
							 .tls = false};

  index_file = fopen(argv[1], "r");
  if(index_file == NULL){
    fprintf(stdout, "Cannot open index file\n");
    return -1;
  }
  get_Index_from_file(index_file, &heartBeat_index, &write_response_index, read_indexes, read_indexes_AkPub, nodes_number);
  fclose(index_file);

  // Set read index of heartbeat
  WAM_init_channel(&ch_read_hearbeat, 1, &privatenet, &k, &a);
	set_channel_index_read(&ch_read_hearbeat, heartBeat_index.index);
  // Set indexes for reading TpaData
  for(i = 0; i < nodes_number; i++){
    //fprintf(stdout, "Setting index: "); hex_print(read_indexes[i].index, INDEX_SIZE);
    WAM_init_channel(&ch_read_attest[i], i, &privatenet, &k, &a);
    set_channel_index_read(&ch_read_attest[i], read_indexes[i].index);
  }
  // Set indexes for reading Tpas AK
  for(i = 0; i < nodes_number; i++){
    //fprintf(stdout, "Setting index: "); hex_print(read_indexes_AkPub[i].index, INDEX_SIZE);
    WAM_init_channel(&ch_read_ak[i], i, &privatenet, &k, &a);
    set_channel_index_read(&ch_read_ak[i], read_indexes_AkPub[i].index);
  }

  // Set write index for response to heartbeat 
  WAM_init_channel(&ch_write_response, 1, &privatenet, &k, &a);
  set_channel_index_write(&ch_write_response, write_response_index);

  // First get all the AKs and construct table in order to recognize each TpaData received from the various Tpas
  cleanUpFolder("/etc/tc/TPA_AKs");
  srand((unsigned int)(time(NULL)));
  for(i = 0; i < nodes_number; i++){
    read_and_save_AKs(&ch_read_ak[i], ak_table, ak_files[i], i);
  }
  fprintf(stdout, "AK map constructed\n");

  while(!WAM_read(&ch_read_hearbeat, nonce, &expected_size)){
    if(ch_read_hearbeat.recv_bytes == expected_size && !have_to_read){
      // new nonce arrived --> read new attestations
      expected_size+=32;
      have_to_read = 1;

      attested_nodes = calloc(nodes_number, sizeof(int));
      read_attest_message = (uint8_t **) malloc(nodes_number * sizeof(uint8_t *));
      for(i = 0; i < nodes_number; i++){
        read_attest_message[i] = (uint8_t *) malloc(sizeof(uint8_t) * (1024 * 100 * 2));
        ch_read_attest[i].recv_bytes = 0;
        ch_read_attest[i].recv_msg = 0;
        offset[i] = 0;
        previous_msg_num[i] = 0;
      }
      nonce_blob.tag = (u_int8_t)0;
      nonce_blob.size = sizeof nonce;
      memcpy(nonce_blob.buffer, nonce, nonce_blob.size);

      for (j = 0; j < nonce_blob.size; j++)
        printf("%02x", nonce_blob.buffer[j]);
      printf("\n");
    }
    i = 0;
    while(have_to_read != 0){
      if(!WAM_read(&ch_read_attest[i], expected_attest_message, &expected_size_attest_message)){            
        if(ch_read_attest[i].recv_msg != previous_msg_num[i]) {
          memcpy(read_attest_message[i] + offset[i], expected_attest_message, DATA_SIZE);
          offset[i] += DATA_SIZE;
          previous_msg_num[i] += 1;
        }
        else if(memcmp(last, read_attest_message[i] + ch_read_attest[i].recv_bytes - sizeof last, sizeof last) == 0 && (attested_nodes[i] == 0)){
          fprintf(stdout, "\nNew quote read! read bytes = %d\n", ch_read_attest[i].recv_bytes);
          parseTPAdata(&TpaData[i], read_attest_message[i]);
          have_to_read += 1;
          
          // Get also pcr10 since we're reading pcrs here
          fprintf(stdout, "Calculating PCR9s ...\n");
          if (!PCR9_calculation(pcr9_sha1, pcr9_sha256, ak_table, TpaData[i], nodes_number)) {
            fprintf(stderr, "PCR9 calculation failed\n");
            goto end;
          }

          // PCR10 calculation + whitelist verify
          fprintf(stdout, "Calculating PCR10s and performing whitelist checks...\n");
          ver_response = verify_PCR10_whitelist(pcr10_sha1, pcr10_sha256, TpaData[i].ima_log_blob);
          fprintf(stdout, "DONE\n");

          fprintf(stdout, "PCR9 sha1: "); hex_print(pcr9_sha1, SHA_DIGEST_LENGTH);
          fprintf(stdout, "PCR10 sha1: "); hex_print(pcr10_sha1, SHA_DIGEST_LENGTH);
          fprintf(stdout, "PCR9 sha256: "); hex_print(pcr9_sha256, SHA256_DIGEST_LENGTH);
          fprintf(stdout, "PCR10 sha256: "); hex_print(pcr10_sha256, SHA256_DIGEST_LENGTH);

          if (!tpm2_checkquote(TpaData[i], nonce_blob, ak_table, nodes_number, pcr10_sha256, pcr10_sha1, pcr9_sha256, pcr9_sha1)) {
            fprintf(stderr, "Error while verifying quote!\n");
            goto end;
          }
          fprintf(stdout, "Quote successfully verified!!!!\n");
          
          // write "response" to heartbeat
          fprintf(stdout, "\n\tSending verification response\n");
          sendRAresponse(&ch_write_response, ver_response);

          attested_nodes[i] = 1;
          fprintf(stdout, "Verified node %d\n", i);

          /*free(TpaData[i].sig_blob.buffer); free(TpaData[i].message_blob.buffer); free(TpaData[i].ak_digest_blob.buffer);
          for(j = 0; i < TpaData[i].ima_log_blob.size; j++)
            free(TpaData[i].ima_log_blob.logEntry[j].template_data);
          free(TpaData[i].ima_log_blob.logEntry);*/
          /*for(j = 0; j < ver_response.number_white_entries; j++)
            free(ver_response.untrusted_entries[j].untrusted_path_name);
          free(ver_response.untrusted_entries);*/
          //free(read_attest_message[i]);
        }
      }
      if(have_to_read == nodes_number + 1){ // +1 because have_to_read start count from 1
        fprintf(stdout, "All quotes read!\n");
        have_to_read = 0;
        free(attested_nodes); // free array --> calloc when new nonce received (so automatically all 0s)
      }
      if((i + 1) == nodes_number) i = 0;
      else i+=1;
    }
  }
  
end:
  for(i = 0; i < nodes_number; i++)
    free(read_attest_message[i]);
  free(read_attest_message);
  free(pcr10_sha1); free(pcr10_sha256); free(pcr9_sha1); free(pcr9_sha256);
  free(ch_read_attest); free(ch_read_ak); 
  free(read_indexes); free(read_indexes_AkPub);
  free(ak_table); free(ak_files);
  free(offset); free(previous_msg_num);
  free(TpaData);
  return 0;
}

bool legal_int(const char *str) {
    while (*str)
        if (!isdigit(*str++))
            return false;
    return true;
}

void get_Index_from_file(FILE *index_file, IOTA_Index *heartBeat_index, IOTA_Index *write_index, 
      IOTA_Index *read_indexes, IOTA_Index *read_indexes_AkPub, int nodes_number) {
  int len_file, i = 0;
  char *data = NULL, read_index_base_str[20] = "read_index_", akread_index_base_str[20] = "AkPub_read_";
  char akpub_index_base_str[20]="pub_key_", index_AkPub_base_str[25]="AkPub_read_pubkey_";

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
  
  free(data);
}

void parseTPAdata(TO_SEND *TpaData, uint8_t *read_attest_message) {
  int acc = 0, i;

  // SIG
  memcpy(&TpaData->sig_blob.tag, read_attest_message + acc, sizeof(u_int8_t));
  acc += sizeof(u_int8_t);
  memcpy(&TpaData->sig_blob.size, read_attest_message + acc, sizeof(u_int16_t));
  acc += sizeof(u_int16_t);
  TpaData->sig_blob.buffer = malloc(TpaData->sig_blob.size * sizeof(u_int8_t));
  memcpy(TpaData->sig_blob.buffer, read_attest_message + acc, sizeof(u_int8_t) * TpaData->sig_blob.size);
  acc += sizeof(u_int8_t) * TpaData->sig_blob.size;
  
  // MESSAGE
  memcpy(&TpaData->message_blob.tag, read_attest_message + acc, sizeof(u_int8_t));
  acc += sizeof(u_int8_t);
  memcpy(&TpaData->message_blob.size, read_attest_message + acc, sizeof(u_int16_t));
  acc += sizeof(u_int16_t);
  TpaData->message_blob.buffer = malloc(TpaData->message_blob.size * sizeof(u_int8_t));
  memcpy(TpaData->message_blob.buffer, read_attest_message + acc, sizeof(u_int8_t) * TpaData->message_blob.size);
  acc += sizeof(u_int8_t) * TpaData->message_blob.size;

  // IMA
  memcpy(&TpaData->ima_log_blob.tag, read_attest_message + acc, sizeof(u_int8_t));
  acc += sizeof(u_int8_t);
  memcpy(&TpaData->ima_log_blob.size, read_attest_message + acc, sizeof(u_int16_t));
  acc += sizeof(u_int16_t);
  memcpy(&TpaData->ima_log_blob.wholeLog, read_attest_message + acc, sizeof(u_int8_t));
  acc += sizeof(u_int8_t);
  
  TpaData->ima_log_blob.logEntry = calloc(TpaData->ima_log_blob.size, sizeof(struct event));

  for (i = 0; i < TpaData->ima_log_blob.size; i++) {
    // send header
    memcpy(&TpaData->ima_log_blob.logEntry[i].header, read_attest_message + acc, sizeof TpaData->ima_log_blob.logEntry[i].header);
    acc += sizeof TpaData->ima_log_blob.logEntry[i].header;
    // send name
    memcpy(TpaData->ima_log_blob.logEntry[i].name, read_attest_message + acc, TpaData->ima_log_blob.logEntry[i].header.name_len * sizeof(char));
    acc += TpaData->ima_log_blob.logEntry[i].header.name_len * sizeof(char);
    // send template data len
    memcpy(&TpaData->ima_log_blob.logEntry[i].template_data_len, read_attest_message + acc, sizeof(u_int32_t));
    acc += sizeof(u_int32_t);
    // send template data
    TpaData->ima_log_blob.logEntry[i].template_data = malloc(TpaData->ima_log_blob.logEntry[i].template_data_len * sizeof(u_int8_t));
    memcpy(TpaData->ima_log_blob.logEntry[i].template_data, read_attest_message + acc, TpaData->ima_log_blob.logEntry[i].template_data_len * sizeof(u_int8_t));
    acc += TpaData->ima_log_blob.logEntry[i].template_data_len * sizeof(u_int8_t);
  }
  // AK MD
  memcpy(&TpaData->ak_digest_blob.tag, read_attest_message + acc, sizeof(u_int8_t));
  acc += sizeof(u_int8_t);
  memcpy(&TpaData->ak_digest_blob.size, read_attest_message + acc, sizeof(u_int16_t));
  acc += sizeof(u_int16_t);
  TpaData->ak_digest_blob.buffer = malloc(TpaData->ak_digest_blob.size * sizeof(u_int8_t));
  memcpy(TpaData->ak_digest_blob.buffer, read_attest_message + acc, sizeof(u_int8_t) * TpaData->ak_digest_blob.size);
  //TpaData->ak_digest_blob.buffer[TpaData->ak_digest_blob.size] = '\0';
}

void sendRAresponse(WAM_channel *ch_send, VERIFICATION_RESPONSE ver_response){
  size_t acc = 0, bytes_to_send = 0;
  int i;
  uint8_t last[4] = "done", *response_buff = NULL;
  
  bytes_to_send += sizeof(uint8_t) + sizeof(uint16_t); // tag + number of untrsuted entries
  for(i = 0; i < ver_response.number_white_entries; i++){
    bytes_to_send += sizeof(uint16_t);
    bytes_to_send += ver_response.untrusted_entries[i].name_len * sizeof(char);
  }
  bytes_to_send += sizeof last;

  response_buff = malloc(sizeof(uint8_t) * bytes_to_send);
  if(response_buff == NULL){
    fprintf(stdout, "OOM\n");
    return;
  }

  memcpy(response_buff + acc, &ver_response.tag, sizeof(uint8_t));
  acc += sizeof(uint8_t);
  memcpy(response_buff + acc, &ver_response.number_white_entries, sizeof(uint16_t));
  acc += sizeof(uint16_t);
  for(i = 0; i < ver_response.number_white_entries; i++){
    memcpy(response_buff + acc, &ver_response.untrusted_entries[i].name_len, sizeof(uint16_t));
    acc += sizeof(uint16_t);
    memcpy(response_buff + acc, ver_response.untrusted_entries[i].untrusted_path_name, ver_response.untrusted_entries[i].name_len * sizeof(char));
    acc += ver_response.untrusted_entries[i].name_len * sizeof(char);
  }
  memcpy(response_buff + acc, last, sizeof last);
  acc += sizeof last;

  fprintf(stdout, "Writing at: "); 
  for(i = 0; i < INDEX_SIZE; i++)
    fprintf(stdout, "%02x", ch_send->current_index.index[i]);
  WAM_write(ch_send, response_buff, (uint32_t)bytes_to_send, false);
  fprintf(stdout, "\n\t DONE WRITING - Sent bytes = %d, acc = %d\n", bytes_to_send, acc);
  
  free(response_buff);
}

bool openAKPub(const char *path, unsigned char **akPub) {
  FILE *ak_pub = fopen(path, "r");
  if (ak_pub == NULL)
  {
    fprintf(stderr, "Could not open file %s \n", path);
    return false;
  }

  char *line = malloc(4096 * sizeof(char));
  char *buff = malloc(4096 * sizeof(char));
  char h1[128], h2[128], h3[128];
  // remove the header of the AK public key
  fscanf(ak_pub, "%s %s %s", h1, h2, h3);
  strcat(h1, " ");
  strcat(h2, " ");
  strcat(h3, "\n");
  strcat(h2, h3);
  strcat(h1, h2);
  strcat(buff, h1);

  while (fscanf(ak_pub, "%s \n", line) == 1)
  {
    if (line[0] == '-')
      break; // To avoid the footer of the AK public key
    strcat(line, "\n");
    strcat(buff, line);
  }

  strcat(line, " ");
  fscanf(ak_pub, "%s %s", h1, h2);
  strcat(h1, " ");
  strcat(h2, "\n");
  strcat(h1, h2);
  strcat(line, h1);
  strcat(buff, line);

  *akPub = (char *)malloc(strlen(buff) * sizeof(char));
  strncpy(*akPub, buff, strlen(buff));

  // printf("%s\n", *akPub);
  fclose(ak_pub);
  free(line);
  free(buff);
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
  free(akPub);
  // do not free ak_path because it points to the actual path, otherwise it will free the actual data and the so it will be lost
  return true;
}

void hex_print(uint8_t *raw_data, size_t raw_size){
  int i;

  for(i = 0; i < raw_size; i++)
    fprintf(stdout, "%02X", raw_data[i]);
  fprintf(stdout, "\n");
}