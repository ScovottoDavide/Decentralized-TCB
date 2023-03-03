#include "read_akpub.h"

void cleanUpFolder(char *path) {
    DIR *folder = opendir(path);
    struct dirent *next_file;
    char filepath[258];

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

int read_AKs_Whitelists(WAM_channel *ch_read, AK_FILE_TABLE *ak_table, WHITELIST_TABLE *whitelist_table, FILE *ak_file, int node_number, volatile int *verifier_status, pthread_mutex_t mutex) {
    unsigned char expected_message[DATA_SIZE], *akPub = NULL, *digest = NULL;
    uint32_t expected_size = DATA_SIZE, offset = 0;
    uint8_t *read_message = (uint8_t *) malloc(sizeof(uint8_t) * DATA_SIZE * 5), last[4] = "done";
    char filename[FILENAME_LEN+FILE_PEM_LEN] = {0}, base_url[16] = "/etc/tc/TPA_AKs/", *tmp;
    size_t akPub_size = 0;
    int acc = 0, i;
    base_url[16] = '\0';

    do{
        WAM_read(ch_read, expected_message, &expected_size);
        if(ch_read->recv_bytes <= 0){
            fprintf(stdout, "Whitelist not uploaded!\n");
            return false;
        }
        memcpy(read_message + offset, expected_message, DATA_SIZE);
        offset += DATA_SIZE;
        pthread_mutex_lock(&mutex); // Lock a mutex for heartBeat_Status
        if(*verifier_status == 1){
            pthread_mutex_unlock(&mutex); // Lock a mutex for heartBeat_Status
            return -2;
        }
        pthread_mutex_unlock(&mutex); // Lock a mutex for heartBeat_Status
    }while(memcmp(last, read_message + ch_read->recv_bytes - sizeof last, sizeof last) != 0);

    memcpy(whitelist_table[node_number].ak_digest, read_message + acc, sizeof(u_int8_t) * SHA256_DIGEST_LENGTH);
    whitelist_table[node_number].ak_digest[SHA256_DIGEST_LENGTH] = '\0';
    acc += sizeof(u_int8_t) * SHA256_DIGEST_LENGTH;
    memcpy(&whitelist_table[node_number].number_of_entries, read_message + acc, sizeof(u_int16_t));
    acc += sizeof(u_int16_t);   
    whitelist_table[node_number].white_entries = malloc(whitelist_table[node_number].number_of_entries * sizeof(struct whitelist_entry));
    for(i = 0; i < whitelist_table[node_number].number_of_entries; i++) {
        memcpy(&whitelist_table[node_number].white_entries[i].digest, read_message + acc, sizeof(u_int8_t) * SHA256_DIGEST_LENGTH * 2);
        whitelist_table[node_number].white_entries[i].digest[SHA256_DIGEST_LENGTH*2] = '\0';
        acc += sizeof(u_int8_t) * SHA256_DIGEST_LENGTH * 2;
        memcpy(&whitelist_table[node_number].white_entries[i].path_len, read_message + acc, sizeof(u_int16_t));
        acc += sizeof(u_int16_t);
        whitelist_table[node_number].white_entries[i].path = malloc(sizeof(u_int8_t) * whitelist_table[node_number].white_entries[i].path_len + 1);
        memcpy(whitelist_table[node_number].white_entries[i].path, read_message + acc, sizeof(u_int8_t) * whitelist_table[node_number].white_entries[i].path_len);
        whitelist_table[node_number].white_entries[i].path[whitelist_table[node_number].white_entries[i].path_len] = '\0';
        acc += sizeof(u_int8_t) * whitelist_table[node_number].white_entries[i].path_len;
    }

    memcpy(&akPub_size, read_message + acc, sizeof(size_t));
    acc += sizeof(size_t);
    akPub = malloc((akPub_size + 1) * sizeof(unsigned char));
    memcpy(akPub, read_message + acc, akPub_size * sizeof(unsigned char));
    akPub[ch_read->recv_bytes] = '\0';

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

    free(read_message);
    free(akPub);
    free(digest);
    free(full_path);
    free(tmp);

    return 0;
}