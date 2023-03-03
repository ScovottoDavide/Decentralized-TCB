#include "all_util.h"
#include "tpm2_createek.h"
#include "tpm2_createak.h"
#include "tpm2_quote.h"
#include "PCR9Extend.h"

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

void get_Index_from_file(FILE *index_file, IOTA_Index *heartBeat_index, IOTA_Index *write_index, IOTA_Index *write_index_AK_Whitelist) {
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
  
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "AK_White_index")->valuestring, INDEX_HEX_SIZE, write_index_AK_Whitelist->index, INDEX_SIZE);
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "AK_White_pub_key")->valuestring, (ED_PUBLIC_KEY_BYTES * 2) + 1, write_index_AK_Whitelist->keys.pub, ED_PUBLIC_KEY_BYTES);
  hex_2_bin(cJSON_GetObjectItemCaseSensitive(json, "AK_White_priv_key")->valuestring, (ED_PRIVATE_KEY_BYTES * 2) + 1, write_index_AK_Whitelist->keys.priv, ED_PRIVATE_KEY_BYTES);

  free(data);
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

bool send_AK_Whitelist_WAM(WAM_channel *ch_send, TO_SEND *TpaData) {
  unsigned char *akPub = NULL;
  unsigned char *digest = NULL;
  WHITELIST_BLOB whitelistBlob;
  uint8_t *to_send_data = NULL, last[4] = "done";
  size_t bytes_to_send = 0, acc = 0, akPub_size = 0;
  int num_entries = 0, i;

  bool res = openAKPub("/etc/tc/ak.pub.pem", &akPub);
  akPub_size = strlen(akPub);
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
  bytes_to_send += sizeof(size_t);
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
  memcpy(to_send_data + acc, &akPub_size, sizeof(size_t));
  acc += sizeof(size_t);
  memcpy(to_send_data + acc, akPub, strlen(akPub) * sizeof(unsigned char));
  acc += strlen(akPub) * sizeof(unsigned char);
  
  memcpy(to_send_data + acc, last, sizeof last);
  acc += sizeof last;
  
  WAM_write(ch_send, to_send_data, (uint32_t)bytes_to_send, false);

  free(digest);
  free(to_send_data);
  for(i = 0; i < whitelistBlob.number_of_entries; i++)
    free(whitelistBlob.white_entries[i].path);
  free(whitelistBlob.white_entries);
  return true;
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