#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <pthread.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#include <time.h>
#include "tpm2_createek.h"
#include "tpm2_createak.h"
#include "tpm2_quote.h"
#include "PCR9Extend.h"
#include "WAM/WAM.h"
//#include "../IMA/ima_read_writeOut_binary.h"

#define BILLION  1000000000L;

int tpm2_getCap_handles_persistent(ESYS_CONTEXT *esys_context);
bool loadAKdigest(TO_SEND *TpaData);
int sendDataToRA_WAM(TO_SEND TpaData, ssize_t *imaLogBytesSize, WAM_channel *ch_send);
bool pcr_check_if_zeros(ESYS_CONTEXT *esys_context);
void get_Index_from_file(FILE *index_file, IOTA_Index *heartBeat_index, IOTA_Index *write_index, IOTA_Index *write_index_AkPub);

int my_gets_avoid_bufferoverflow(char *buffer, size_t buffer_len);
void PoC_TPA(void *input);
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
  pthread_t th_tpa, th_menu;

  if(argc != 2){
    fprintf(stdout, "Please specify the file path of the 'indexation' file\n");
    return -1;
  }    

  pthread_create(&th_menu, NULL, (void *)&PoC_TPA, (void *) argv[1]);
  pthread_create(&th_menu, NULL, (void *)&menu, NULL);

  pthread_join(th_tpa, NULL);
  pthread_join(th_menu, NULL);
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

void PoC_TPA(void *input) {
  char *file_index_path_name = ((char *)input);
  struct timespec start, stop, delta;
  double accum;

  // TPM
  TSS2_RC tss_r;
  ESYS_CONTEXT *esys_context = NULL;
  TSS2_TCTI_CONTEXT *tcti_context = NULL;
  int persistent_handles = 0, i;
  TO_SEND TpaData;
  ssize_t imaLogBytesSize = 0;

  // WAM
  uint8_t mykey[]="supersecretkeyforencryptionalby";
	WAM_channel ch_read_hearbeat, ch_send, ch_send_AkPub;
	WAM_AuthCtx a; a.type = AUTHS_NONE;
	WAM_Key k; k.data = mykey; k.data_len = (uint16_t) strlen((char*)mykey);
	uint8_t nonce[32];
	uint32_t expected_size = 32;
	uint8_t ret = 0;
  IOTA_Index heartBeat_index, write_index, write_index_AkPub;
  FILE *index_file;

	IOTA_Endpoint privatenet = {.hostname = "130.192.86.15\0",
							 .port = 14000,
							 .tls = false};

  index_file = fopen(file_index_path_name, "r");
  if(index_file == NULL){
    fprintf(stdout, "Cannot open file\n");
    return ;
  }
  get_Index_from_file(index_file, &heartBeat_index, &write_index, &write_index_AkPub);
  fclose(index_file);
	
  // set read index of heatbeat
  WAM_init_channel(&ch_read_hearbeat, 1, &privatenet, &k, &a);
	set_channel_index_read(&ch_read_hearbeat, heartBeat_index.index);
  // set write index for the AkPub
  WAM_init_channel(&ch_send_AkPub, 1, &privatenet, &k, &a);
  set_channel_index_write(&ch_send_AkPub, write_index_AkPub);
  // Set write index for the quote 
  WAM_init_channel(&ch_send, 1, &privatenet, &k, &a);
  set_channel_index_write(&ch_send, write_index);

	while(!WAM_read(&ch_read_hearbeat, nonce, &expected_size)){
    if(ch_read_hearbeat.recv_bytes == expected_size){
      expected_size+=32;

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
      /**
      Assumption: Ek is at NV-Index 0x81000000, AK is at NV-Index 0x81000001
      and they are the only persistent handles in NV-RAM.
      See if optimizable!
      **/
      // Read the # of persistent handles: if 0 proceed in creating EK and AK, otherwise DO NOT
      persistent_handles = tpm2_getCap_handles_persistent(esys_context);
      if (persistent_handles < 0) {
        printf("Error while reading persistent handles!\n");
        return ;
      }
      if (!persistent_handles) {
        fprintf(stdout, "Generating EK...\n");
        tss_r = tpm2_createek(esys_context);
        if (tss_r != TSS2_RC_SUCCESS) {
          printf("Error in tpm2_createek\n");
          return ;
        }
        fprintf(stdout, "Generating AK...\n");
        tss_r = tpm2_createak(esys_context);
        if (tss_r != TSS2_RC_SUCCESS) {
          printf("\tError creating AK\n");
          return ;
        }
        tpm2_getCap_handles_persistent(esys_context);
      }
      if (pcr_check_if_zeros(esys_context)) {
        // Extend both
        ExtendPCR9(esys_context, "sha1");
        fprintf(stdout, "PCR9 sha1 extended\n");
        ExtendPCR9(esys_context, "sha256");
        fprintf(stdout, "PCR9 sha256 extended\n");
      }

      if(!loadAKdigest(&TpaData)) {
        fprintf(stdout, "Could not load AK pub digest!\n");
        return ;
      }

      tss_r = tpm2_quote(esys_context, &TpaData, imaLogBytesSize);
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

      if( clock_gettime( CLOCK_REALTIME, &stop) == -1 ) {
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
  }

end:
  free(TpaData.ak_digest_blob.buffer);
  for(i = 0; i < TpaData.ima_log_blob.size; i++)
    free(TpaData.ima_log_blob.logEntry[i].template_data);
  return ;
}

void get_Index_from_file(FILE *index_file, IOTA_Index *heartBeat_index, IOTA_Index *write_index, IOTA_Index *write_index_AkPub) {
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

  free(data);
}

bool loadAKdigest(TO_SEND *TpaData) {
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

  free(digest);
  return true;
}

int tpm2_getCap_handles_persistent(ESYS_CONTEXT *esys_context) {
  TSS2_RC tss_r;
  TPM2_CAP capability = TPM2_CAP_HANDLES;
  UINT32 property = TPM2_HR_PERSISTENT;
  UINT32 propertyCount = TPM2_MAX_CAP_HANDLES;
  TPMS_CAPABILITY_DATA *capabilityData;
  TPMI_YES_NO moreData;

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
    return capabilityData->data.handles.count;
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

  WAM_write(ch_send, to_send_data, (uint32_t)bytes_to_send, false);
  fprintf(stdout, "DONE WRITING - Sent bytes = %d, ima = %d\n\n", bytes_to_send, *imaLogBytesSize);

  free(to_send_data);
  //free(TpaData.ima_log_blob.logEntry);
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
