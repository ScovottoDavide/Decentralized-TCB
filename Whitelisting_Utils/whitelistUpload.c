#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <unistd.h>
#include "/home/pi/WAM/WAM.h"

struct whitelist_entry {
    u_int8_t digest[SHA256_DIGEST_LENGTH*2+1];
    u_int16_t path_len;
    char *path;
};

typedef struct {
  u_int8_t ak_digest[SHA256_DIGEST_LENGTH+1];
  u_int16_t number_of_entries;
  struct whitelist_entry *white_entries;
} WHITELIST_BLOB;

bool openAKPub(const char *path, unsigned char **akPub);
bool loadWhitelist(FILE *fp, struct whitelist_entry *white_entries, int size);
int computeDigestEVP(unsigned char* akPub, const char* sha_alg, unsigned char *digest);
void get_Index_from_file(FILE *index_file, IOTA_Index *write_index_whitelist);
bool sendWhitelist_WAM(WAM_channel *ch_send_whitelist);
void hex_print(uint8_t *raw_data, size_t raw_size);

int main(int argc, char *argv[]) {
  uint8_t mykey[]="supersecretkeyforencryptionalby";
  WAM_AuthCtx a; a.type = AUTHS_NONE;
  WAM_Key k; k.data = mykey; k.data_len = (uint16_t) strlen((char*)mykey);
  WAM_channel ch_send_whitelist;
  IOTA_Index write_index_whitelist;
  FILE *index_file;

  IOTA_Endpoint privatenet = {.hostname = "130.192.86.15\0",
              .port = 14000,
              .tls = false};
  
  if(argc != 2){
    fprintf(stdout, "Please specify the file path of the 'indexes' file\n");
    return -1;
  }    
  index_file = fopen(argv[1], "r");
  if(index_file == NULL){
    fprintf(stdout, "Cannot open file\n");
    return -1;
  }
  get_Index_from_file(index_file, &write_index_whitelist);
  fclose(index_file);

  // set write index for the AkPub & whitelist
  WAM_init_channel(&ch_send_whitelist, 1, &privatenet, &k, &a);
  set_channel_index_write(&ch_send_whitelist, write_index_whitelist);

  sendWhitelist_WAM(&ch_send_whitelist);
}

void get_Index_from_file(FILE *index_file, IOTA_Index *write_index_whitelist) {
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
  
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "whitelist_index")->valuestring, INDEX_HEX_SIZE, write_index_whitelist->index, INDEX_SIZE);
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "whitelist_pub_key")->valuestring, (ED_PUBLIC_KEY_BYTES * 2) + 1, write_index_whitelist->keys.pub, ED_PUBLIC_KEY_BYTES);
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "whitelist_priv_key")->valuestring, (ED_PRIVATE_KEY_BYTES * 2) + 1, write_index_whitelist->keys.priv, ED_PRIVATE_KEY_BYTES);

  free(data);
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

  whitelist_fp = fopen("whitelist", "rb");
  if (!whitelist_fp) {
    fprintf(stdout, "\nNo whitelist file found! Skipping whitelist verification!\n\n");
  } else {
    fscanf(whitelist_fp, "%d", &num_entries);
    whitelistBlob.number_of_entries = num_entries;
    whitelistBlob.white_entries = malloc(num_entries * sizeof(struct whitelist_entry));
    if (!whitelistBlob.white_entries) {
      fprintf(stdout, "OOM %d\n", num_entries);
      exit(-1);
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

  return true;
}

void hex_print(uint8_t *raw_data, size_t raw_size){
  int i;

  for(i = 0; i < raw_size; i++)
    fprintf(stdout, "%02X", raw_data[i]);
  fprintf(stdout, "\n");
}