#include "read_akpub.h"

void cleanUpFolder(char *path) {
    DIR *folder = opendir(path);
    struct dirent *next_file;
    char filepath[256];

    while( (next_file = readdir(folder)) != NULL ){
        if (!strcmp(".", next_file->d_name) || !strcmp("..", next_file->d_name))
            continue;
        //fprintf(stdout, "removing file %s\n", next_file->d_name);
        sprintf(filepath, "%s/%s", path, next_file->d_name);
        remove(filepath);
    }
    closedir(folder);
}

char* rand_str(size_t length) {
    char charset[] = "0123456789"
                     "abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char *dest = malloc(length * sizeof(char));

    for(int i = 0; i < length; i++){
        size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
        dest[i] = charset[index];
    }
    dest[length] = '\0';
    return dest;
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

// For now 1 node, 1 channel, 1 index!
int read_and_save_AKs(WAM_channel *ch_read_ak, AK_FILE_TABLE *ak_table, FILE *ak_file, int node_number, volatile int *verifier_status, pthread_mutex_t mutex) {
    unsigned char expected_message[DATA_SIZE], *akPub = NULL, *digest = NULL;
    uint32_t expected_size = DATA_SIZE;
    char filename[FILENAME_LEN+FILE_PEM_LEN] = {0}, base_url[16] = "/etc/tc/TPA_AKs/", *tmp;
    base_url[16] = '\0';

    while(ch_read_ak->recv_msg == 0){
        WAM_read(ch_read_ak, expected_message, &expected_size);
        pthread_mutex_lock(&mutex); // Lock a mutex for heartBeat_Status
        if(*verifier_status == 1){
            pthread_mutex_unlock(&mutex); // Lock a mutex for heartBeat_Status
            return -2;
        }
        pthread_mutex_unlock(&mutex); // Lock a mutex for heartBeat_Status
    }

    akPub = malloc((ch_read_ak->recv_bytes + 1) * sizeof(unsigned char));
    memcpy(akPub, expected_message, ch_read_ak->recv_bytes);
    akPub[ch_read_ak->recv_bytes] = '\0';

    // compute the filename and the whole path
    tmp = rand_str(FILENAME_LEN);
    memcpy(&filename, tmp, FILENAME_LEN);
    strcat(filename, ".pub.pem");
    filename[FILENAME_LEN + FILE_PEM_LEN] = '\0';
    u_int8_t *full_path = malloc((sizeof base_url + sizeof filename + 1) * sizeof(u_int8_t));
    memcpy(full_path, base_url, sizeof base_url*sizeof(u_int8_t));
    memcpy(full_path + sizeof base_url, filename, sizeof filename);
    full_path[sizeof base_url + sizeof filename] = '\0';

    // compute ak digest 
    digest = malloc((SHA256_DIGEST_LENGTH + 1)*sizeof(unsigned char));
    int md_len = computeDigestEVP(akPub, "sha256", digest);
    if(md_len <= 0)
        return -1;
    digest[SHA256_DIGEST_LENGTH] = '\0';
    
    // save data in the struct
    ak_table[node_number].path_name = malloc((sizeof base_url + sizeof filename + 1) * sizeof(u_int8_t));
    memcpy(ak_table[node_number].ak_md, digest, SHA256_DIGEST_LENGTH * sizeof(unsigned char));
    strncpy(ak_table[node_number].path_name, full_path, sizeof  base_url + sizeof filename);
    ak_table[node_number].path_name[sizeof  base_url + sizeof filename] = '\0';

    // save aks to file  
    ak_file = fopen(full_path, "w");
    fwrite(akPub, 1, strlen(akPub), ak_file);
    fclose(ak_file);

    free(akPub);
    free(digest);
    free(full_path);
    free(tmp);

    return 0;
}