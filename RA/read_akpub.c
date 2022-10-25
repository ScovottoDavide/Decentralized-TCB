#include "read_akpub.h"

void rand_str(char *dest, size_t length) {
    char charset[] = "0123456789"
                     "abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    srand((unsigned int)(time(NULL)));

    while (length-- > 0) {
        size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
        *dest++ = charset[index];
    }
    *dest = '\0';
}

int computeDigestEVP(unsigned char* akPub, const char* sha_alg, unsigned char **digest){
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
  EVP_DigestFinal_ex(mdctx, *digest, &md_len);
  EVP_MD_CTX_free(mdctx);

  return md_len;
}

// For now 1 node, 1 channel, 1 index!
bool read_and_save_AKs(WAM_channel *ch_read_ak, AK_FILE_TABLE **ak_table, int nodes_number) {
    unsigned char expected_message[DATA_SIZE], *akPub = NULL, *digest = NULL;
    uint32_t expected_size = DATA_SIZE;
    char filename[FILENAME_LEN+FILE_PEM_LEN], base_url[16] = "/etc/tc/TPA_AKs/";
    FILE **ak_files;
    base_url[16] = '\0';

    while(ch_read_ak->recv_msg == 0)
        WAM_read(ch_read_ak, expected_message, &expected_size);
    
    akPub = malloc((ch_read_ak->recv_bytes + 1) * sizeof(unsigned char));
    memcpy(akPub, expected_message, ch_read_ak->recv_bytes);
    akPub[ch_read_ak->recv_bytes] = '\0';

    // compute the filename and the whole path
    rand_str(filename, FILENAME_LEN);
    strcat(filename, ".pub.pem");
    filename[FILENAME_LEN + FILE_PEM_LEN] = '\0';
    u_int8_t *full_path = malloc((sizeof base_url + sizeof filename + 1) * sizeof(u_int8_t));
    memcpy(full_path, base_url, sizeof base_url*sizeof(u_int8_t));
    memcpy(full_path + sizeof base_url, filename, sizeof filename);
    full_path[sizeof base_url + sizeof filename] = '\0';

    // compute ak digest 
    digest = malloc((SHA256_DIGEST_LENGTH + 1)*sizeof(unsigned char));
    int md_len = computeDigestEVP(akPub, "sha256", &digest);
    if(md_len <= 0)
        return false;
    digest[SHA256_DIGEST_LENGTH] = '\0';

    // save data in the struct
    *ak_table = malloc(nodes_number * sizeof(AK_FILE_TABLE));
    ak_table[0]->path_name = malloc((sizeof base_url + sizeof filename) * sizeof(u_int8_t));
    memcpy(ak_table[0]->ak_md, digest, SHA256_DIGEST_LENGTH * sizeof(unsigned char));
    strncpy(ak_table[0]->path_name, full_path, sizeof  base_url + sizeof filename);

    // save aks to file  
    ak_files = malloc(nodes_number * sizeof(FILE *));
    ak_files[0] = fopen(full_path, "w");
    fwrite(akPub, 1, strlen(akPub), ak_files[0]);
    fclose(ak_files[0]);

    free(akPub);
    free(digest);
    free(full_path);
    free(ak_files);
}