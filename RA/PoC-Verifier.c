#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/rand.h>
#include "whitelist_verify.h"
#include "../../WAM/WAM.h"

//bool pcr_get_pcr_byId(TPML_PCR_SELECTION pcr_select, tpm2_pcrs *pcrs, TPM2B_DIGEST *pcr9_sha1, TPM2B_DIGEST *pcr9_sha256, int id);
bool openAKPub(const char *path, unsigned char **akPub);
int computeDigestEVP(unsigned char *akPub, const char *sha_alg, unsigned char **digest);
int computePCRsoftBinding(unsigned char *pcr_concatenated, const char *sha_alg, unsigned char **digest, int size);
bool PCR9_calculation(unsigned char **expected_PCR9sha1, unsigned char **expected_PCR9sha256);
void get_Index_from_file(FILE *index_file, IOTA_Index *heartBeat_index, IOTA_Index *write_index, IOTA_Index **read_indexes);
void parseTPAdata(TO_SEND *TpaData, uint8_t *read_attest_message);
void sendRAresponse(WAM_channel *ch_send, VERIFICATION_RESPONSE ver_response);

int main(int argc, char const *argv[])
{
  int i, j;
  TO_SEND TpaData; VERIFICATION_RESPONSE ver_response;
  FILE *index_file;
  
  IOTA_Index heartBeat_index, *read_indexes, write_response_index;
  uint8_t mykey[]="supersecretkeyforencryptionalby";
	WAM_channel ch_read_hearbeat, ch_read_attest, ch_write_response;
	WAM_AuthCtx a; a.type = AUTHS_NONE;
	WAM_Key k; k.data = mykey; k.data_len = (uint16_t) strlen((char*)mykey);
	
  uint32_t expected_size = 32, expected_size_attest_message = DATA_SIZE, offset = 0;
	uint8_t ret = 0, *read_attest_message = NULL, expected_attest_message[DATA_SIZE], have_to_read = 0, nonce[32], last[4] = "done";
  uint16_t previous_msg_num = 0;

  unsigned char *pcr9_sha1 = NULL, *pcr9_sha256 = NULL, *pcr10_sha256 = NULL, *pcr10_sha1 = NULL;

  IOTA_Endpoint privatenet = {.hostname = "130.192.86.15\0",
							 .port = 14265,
							 .tls = false};

  index_file = fopen("/etc/tc/RA_index_node2.json", "r");
  if(index_file == NULL){
    fprintf(stdout, "Cannot open file\n");
    return -1;
  }
  get_Index_from_file(index_file, &heartBeat_index, &write_response_index, &read_indexes);
  fclose(index_file);

  // Set read index of heatbeat
  WAM_init_channel(&ch_read_hearbeat, 1, &privatenet, &k, &a);
	set_channel_index_read(&ch_read_hearbeat, heartBeat_index.index);
  // Set read write index from the file
  WAM_init_channel(&ch_read_attest, 1, &privatenet, &k, &a);
  set_channel_index_read(&ch_read_attest, read_indexes[0].index);

  // Set write index for response to heartbeat 
  WAM_init_channel(&ch_write_response, 1, &privatenet, &k, &a);
  set_channel_index_write(&ch_write_response, write_response_index);

  while(!WAM_read(&ch_read_hearbeat, nonce, &expected_size)){
    if(ch_read_hearbeat.recv_bytes == expected_size && !have_to_read){
      // new nonce arrived --> read new attestations
      expected_size+=32;
      have_to_read = 1;

      if(read_attest_message != NULL)
        free(read_attest_message);
      read_attest_message = malloc(sizeof(uint8_t) * (1024 * 100 * 2));
      
      ch_read_attest.recv_bytes = 0;
      ch_read_attest.recv_msg = 0;
      offset = 0;
      previous_msg_num = 0;

      TpaData.nonce_blob.tag = (u_int8_t)0;
      TpaData.nonce_blob.size = sizeof nonce;
      memcpy(TpaData.nonce_blob.buffer, nonce, TpaData.nonce_blob.size);

      for (i = 0; i < TpaData.nonce_blob.size; i++)
        printf("%02x", TpaData.nonce_blob.buffer[i]);
      printf("\n");
    }
    if(have_to_read) {
      if(!WAM_read(&ch_read_attest, expected_attest_message, &expected_size_attest_message)){            
        if(ch_read_attest.recv_msg != previous_msg_num) {
          memcpy(read_attest_message + offset, expected_attest_message, DATA_SIZE);
          offset += DATA_SIZE;
          previous_msg_num += 1;
        }
        else if(memcmp(last, read_attest_message + ch_read_attest.recv_bytes - sizeof last, sizeof last) == 0){
          fprintf(stdout, "\nNew quote read! read bytes = %d\n", ch_read_attest.recv_bytes);
          parseTPAdata(&TpaData, read_attest_message);
          have_to_read = 0;
          
          // Get also pcr10 since we're reading pcrs here
          fprintf(stdout, "Calculating PCR9s ...\n");
          if (!PCR9_calculation(&pcr9_sha1, &pcr9_sha256)) {
            fprintf(stderr, "PCR9 calculation failed\n");
            exit(-1);
          }

          // PCR10 calculation + whitelist verify
          fprintf(stdout, "Calculating PCR10s and performing whitelist checks...\n");
          verify_PCR10_whitelist(&pcr10_sha1, &pcr10_sha256, TpaData.ima_log_blob, &ver_response);

          if (!tpm2_checkquote(TpaData, pcr10_sha256, pcr10_sha1, pcr9_sha256, pcr9_sha1)) {
            fprintf(stderr, "Error while verifying quote!\n");
            exit(-1);
          }
          fprintf(stdout, "Quote successfully verified!!!!\n");
          
          // write "response" to heartbeat
          fprintf(stdout, "\n\tSending verification response\n");
          sendRAresponse(&ch_write_response, ver_response);

          for(i = 0; i < TpaData.ima_log_blob.size; i++){
            free(TpaData.ima_log_blob.logEntry[i].template_data);
          }
          free(TpaData.ima_log_blob.logEntry);
          free(TpaData.sig_blob.buffer);
          free(TpaData.message_blob.buffer);
          free(pcr10_sha1);
          free(pcr10_sha256);
          free(pcr9_sha1);
          free(pcr9_sha256);
        }
      }
    }
  }
  
  return 0;
}

void get_Index_from_file(FILE *index_file, IOTA_Index *heartBeat_index, IOTA_Index *write_index, IOTA_Index **read_indexes) {
  int len_file;
  char *data = NULL;

  *read_indexes = malloc(sizeof(IOTA_Index));

  //get len of file
  fseek(index_file, 0, SEEK_END);
  len_file = ftell(index_file);
  fseek(index_file, 0, SEEK_SET);

   // read the data from the file 
  data = (char*) malloc(len_file + 1);
  fread(data, 1, len_file, index_file);
  data[len_file] = '\0';

  cJSON *json = cJSON_Parse(data);

  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "index")->valuestring, INDEX_HEX_SIZE, write_index->index, INDEX_SIZE);
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "pub_key")->valuestring, (ED_PUBLIC_KEY_BYTES * 2) + 1, write_index->keys.pub, ED_PUBLIC_KEY_BYTES);
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "priv_key")->valuestring, (ED_PRIVATE_KEY_BYTES * 2) + 1, write_index->keys.priv, ED_PRIVATE_KEY_BYTES);

  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "heartbeat")->valuestring, INDEX_HEX_SIZE, heartBeat_index->index, INDEX_SIZE);
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "heartBeat_pub_key")->valuestring, (ED_PUBLIC_KEY_BYTES * 2) + 1, heartBeat_index->keys.pub, ED_PUBLIC_KEY_BYTES);

  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "read_index_1")->valuestring, INDEX_HEX_SIZE, read_indexes[0]->index, INDEX_SIZE);
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "pub_key_1")->valuestring, (ED_PUBLIC_KEY_BYTES * 2) + 1, read_indexes[0]->keys.pub, ED_PUBLIC_KEY_BYTES);
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
  acc += sizeof(u_int8_t) * sizeof(u_int8_t) * TpaData->message_blob.size;

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
  for(i = 0; i < ver_response.number_white_entries; i++)
    free(ver_response.untrusted_entries[i].untrusted_path_name);
  free(ver_response.untrusted_entries);
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

int computeDigestEVP(unsigned char *akPub, const char *sha_alg, unsigned char **digest) {
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
  EVP_DigestUpdate(mdctx, akPub, strlen(akPub));
  EVP_DigestFinal_ex(mdctx, *digest, &md_len);
  EVP_MD_CTX_free(mdctx);

  return md_len;
}

int computePCRsoftBinding(unsigned char *pcr_concatenated, const char *sha_alg, unsigned char **digest, int size) {
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
  EVP_DigestFinal_ex(mdctx, *digest, &md_len);
  EVP_MD_CTX_free(mdctx);

  return md_len;
}

bool PCR9_calculation(unsigned char **expected_PCR9sha1, unsigned char **expected_PCR9sha256) {
  int i;
  unsigned char *akPub = NULL;
  unsigned char *digest_sha1 = NULL;
  unsigned char *digest_sha256 = NULL;
  
  if (!openAKPub("/etc/tc/ak.pub.pem", &akPub)) {
    fprintf(stderr, "Could not read AK pub\n");
    return false;
  }

  digest_sha1 = malloc((EVP_MAX_MD_SIZE) * sizeof(unsigned char));
  digest_sha256 = malloc((EVP_MAX_MD_SIZE) * sizeof(unsigned char));
  int md_len_sha1 = computeDigestEVP(akPub, "sha1", &digest_sha1);
  if (md_len_sha1 <= 0)
    return false;
  int md_len_sha256 = computeDigestEVP(akPub, "sha256", &digest_sha256);
  if (md_len_sha256 <= 0)
    return false;

  u_int8_t *pcr_sha1;
  pcr_sha1 = calloc((SHA_DIGEST_LENGTH * 2 + 1), sizeof(u_int8_t));
  int k = SHA_DIGEST_LENGTH;
  for (i = 0; i < md_len_sha1; i++)
    pcr_sha1[k++] = (u_int8_t)digest_sha1[i];
  pcr_sha1[SHA_DIGEST_LENGTH * 2] = '\0';
  *expected_PCR9sha1 = malloc((SHA_DIGEST_LENGTH + 1) * sizeof(unsigned char));
  md_len_sha1 = computePCRsoftBinding(pcr_sha1, "sha1", expected_PCR9sha1, SHA_DIGEST_LENGTH * 2);
  if (md_len_sha1 <= 0)
    return false;

  free(pcr_sha1);
  free(digest_sha1);

  u_int8_t *pcr_sha256;
  pcr_sha256 = calloc(SHA256_DIGEST_LENGTH * 2 + 1, sizeof(u_int8_t));
  k = SHA256_DIGEST_LENGTH;
  for (i = 0; i < md_len_sha256; i++)
  {
    pcr_sha256[k++] = digest_sha256[i];
  }

  pcr_sha256[SHA256_DIGEST_LENGTH * 2] = '\0';
  *expected_PCR9sha256 = malloc((SHA256_DIGEST_LENGTH) * sizeof(unsigned char));
  md_len_sha256 = computePCRsoftBinding(pcr_sha256, "sha256", expected_PCR9sha256, SHA256_DIGEST_LENGTH * 2);
  if (md_len_sha256 <= 0)
    return false;

  free(pcr_sha256);
  free(digest_sha256);

  free(akPub);
  return true;
}
