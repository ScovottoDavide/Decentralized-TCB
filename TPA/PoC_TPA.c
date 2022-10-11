#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#include "tpm2_createek.h"
#include "tpm2_createak.h"
#include "tpm2_quote.h"
#include "PCR9Extend.h"
#include "../../WAM/WAM.h"
#include "./cjson/cJSON.h"
//#include "../IMA/ima_read_writeOut_binary.h"

int tpm2_getCap_handles_persistent(ESYS_CONTEXT *esys_context);
int sendDataToRA_WAM(TO_SEND TpaData, ssize_t *imaLogBytesSize, WAM_channel ch_send);
bool pcr_check_if_zeros(ESYS_CONTEXT *esys_context);
void hextobin(unsigned char *v, unsigned char *s, size_t n);
void get_Index_from_file(FILE *index_file, IOTA_Index *heartBeat_index, IOTA_Index *write_index, IOTA_Index **read_indexes);

int main() {
  // TPM
  TSS2_RC tss_r;
  ESYS_CONTEXT *esys_context = NULL;
  TSS2_TCTI_CONTEXT *tcti_context = NULL;
  int persistent_handles = 0, i;
  TO_SEND TpaData;
  ssize_t imaLogBytesSize = 0;

  // WAM
  uint8_t mykey[]="supersecretkeyforencryptionalby";
	WAM_channel ch_read_hearbeat, ch_send;
	WAM_AuthCtx a; a.type = AUTHS_NONE;
	WAM_Key k; k.data = mykey; k.data_len = (uint16_t) strlen((char*)mykey);
	uint8_t nonce[32];
	uint32_t expected_size = 32;
	uint8_t ret = 0;
  IOTA_Index heartBeat_index, write_index;
  FILE *index_file;

  tss_r = Tss2_TctiLdr_Initialize(NULL, &tcti_context);
  if (tss_r != TSS2_RC_SUCCESS) {
    printf("Could not initialize tcti context\n");
    exit(-1);
  }

  tss_r = Esys_Initialize(&esys_context, tcti_context, NULL);
  if (tss_r != TSS2_RC_SUCCESS) {
    printf("Could not initialize esys context\n");
    exit(-1);
  }

	IOTA_Endpoint privatenet = {.hostname = "130.192.86.15\0",
							 .port = 14265,
							 .tls = false};

  index_file = fopen("/etc/tc/index_node1.txt", "r");
  if(index_file == NULL){
    fprintf(stdout, "Cannot open file\n");
    return -1;
  }
  get_Index_from_file(index_file, &heartBeat_index, &write_index, NULL);
  fclose(index_file);
	
  // set read index of heatbeat
  WAM_init_channel(&ch_read_hearbeat, 1, &privatenet, &k, &a);
	set_channel_index_read(&ch_read_hearbeat, heartBeat_index.index);
  // Set read write index from the file
  WAM_init_channel(&ch_send, 1, &privatenet, &k, &a);
  set_channel_index_write(&ch_send, write_index);

	while(!WAM_read(&ch_read_hearbeat, nonce, &expected_size)){
    if(ch_read_hearbeat.recv_bytes == expected_size){
      expected_size+=32;

      TpaData.nonce_blob.tag = (u_int8_t)0;
      TpaData.nonce_blob.size = sizeof nonce;
      memcpy(TpaData.nonce_blob.buffer, nonce, TpaData.nonce_blob.size);

      /**
      Assumption: Ek is at NV-Index 0x80000000, AK is at NV-Index 0x80000001
      and they are the only persistent handles in NV-RAM.
      See if optimizable!
      **/
      // Read the # of persistent handles: if 0 proceed in creating EK and AK, otherwise DO NOT
      persistent_handles = tpm2_getCap_handles_persistent(esys_context);
      if (persistent_handles < 0) {
        printf("Error while reading persistent handles!\n");
        exit(-1);
      }

      if (!persistent_handles) {
        fprintf(stdout, "Generating EK...\n");
        tss_r = tpm2_createek(esys_context);
        if (tss_r != TSS2_RC_SUCCESS) {
          printf("Error in tpm2_createek\n");
          exit(-1);
        }

        fprintf(stdout, "Generating AK...\n");
        tss_r = tpm2_createak(esys_context);
        if (tss_r != TSS2_RC_SUCCESS) {
          printf("\tError creating AK\n");
          exit(-1);
        }

        tpm2_getCap_handles_persistent(esys_context);
      }

      if (pcr_check_if_zeros(esys_context)) {
        // Extend both
        ExtendPCR9(esys_context, "sha1");
        ExtendPCR9(esys_context, "sha256");
      }

      tss_r = tpm2_quote(esys_context, &TpaData, imaLogBytesSize);
      if (tss_r != TSS2_RC_SUCCESS) {
        printf("Error while computing quote!\n");
        exit(-1);
      }

      /** SEND DATA TO THE REMOTE ATTESTOR */
      sendDataToRA_WAM(TpaData, &imaLogBytesSize, ch_send); 
    }
  }

  free(esys_context);
  free(tcti_context);
  return 0;
}

void hextobin(unsigned char *v, unsigned char *s, size_t n) {
	int i;
	char _t[3];
	unsigned char *p = s;
	for (i=0; i<n; ++i) {
		memcpy(_t, p, 2);
		_t[2] = '\0';
		v[i] = (int)strtol(_t, NULL, 16);
		p += 2;
	}
}

void get_Index_from_file(FILE *index_file, IOTA_Index *heartBeat_index, IOTA_Index *write_index, IOTA_Index **read_indexes){
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
}

int tpm2_getCap_handles_persistent(ESYS_CONTEXT *esys_context)
{
  TSS2_RC tss_r;
  TPM2_CAP capability = TPM2_CAP_HANDLES;
  UINT32 property = TPM2_HR_PERSISTENT;
  UINT32 propertyCount = TPM2_MAX_CAP_HANDLES;
  TPMS_CAPABILITY_DATA *capabilityData;
  TPMI_YES_NO moreData;

  printf("\nReading persistent handles!\n");
  tss_r = Esys_GetCapability(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
    ESYS_TR_NONE, capability, property,
    propertyCount, &moreData, &capabilityData);
    if (tss_r != TSS2_RC_SUCCESS)
    {
      printf("Error while reading persistent handles\n");
      return -1;
    }
    int i = 0;
    printf("Persistent handles present in NVRAM are %d\n", capabilityData->data.handles.count);
    for (i = 0; i < capabilityData->data.handles.count; i++)
    {
      printf("Persistent Handle: 0x%X\n", capabilityData->data.handles.handle[i]);
    }
    return capabilityData->data.handles.count;
  }

  int sendDataToRA_WAM(TO_SEND TpaData, ssize_t *imaLogBytesSize, WAM_channel ch_send) {
    uint8_t *to_send_data;
    size_t bytes_to_send = 0, acc = 0;
    uint32_t pipi = 0;
    int i = 0;
    uint8_t last[4] = "done";

    // pcrs
    bytes_to_send += sizeof(u_int8_t) + sizeof(TPML_PCR_SELECTION) + (sizeof TpaData.pcrs_blob.pcrs.count) + (sizeof(TPML_DIGEST) * TpaData.pcrs_blob.pcrs.count);
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

    to_send_data = malloc(sizeof(u_int8_t) * bytes_to_send);
    if(to_send_data == NULL){
      fprintf(stdout, "OOM\n");
      return -1;
    }

    memcpy(to_send_data, &TpaData.pcrs_blob.tag, sizeof(u_int8_t));
    acc += sizeof(u_int8_t);
    memcpy(to_send_data + acc, &TpaData.pcrs_blob.pcr_selection, sizeof(TPML_PCR_SELECTION));
    acc += sizeof(TPML_PCR_SELECTION);
    memcpy(to_send_data + acc, &TpaData.pcrs_blob.pcrs.count, sizeof TpaData.pcrs_blob.pcrs.count);
    acc += sizeof TpaData.pcrs_blob.pcrs.count;
    memcpy(to_send_data + acc, &TpaData.pcrs_blob.pcrs.pcr_values, sizeof(TPML_DIGEST) * TpaData.pcrs_blob.pcrs.count);
    acc += sizeof(TPML_DIGEST) * TpaData.pcrs_blob.pcrs.count;

    memcpy(to_send_data + acc, &TpaData.sig_blob.tag, sizeof(u_int8_t));
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
    acc += sizeof(u_int8_t) * sizeof(u_int8_t) * TpaData.message_blob.size;

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
      // send name
      memcpy(to_send_data + acc, &TpaData.ima_log_blob.logEntry[i].name, TpaData.ima_log_blob.logEntry[i].header.name_len * sizeof(char));
      acc += TpaData.ima_log_blob.logEntry[i].header.name_len * sizeof(char);
      // send template data len
      memcpy(to_send_data + acc, &TpaData.ima_log_blob.logEntry[i].template_data_len, sizeof(u_int32_t));
      acc += sizeof(u_int32_t);
      // send template data
      memcpy(to_send_data + acc, &TpaData.ima_log_blob.logEntry[i].template_data, TpaData.ima_log_blob.logEntry[i].template_data_len * sizeof(u_int8_t));
      acc += TpaData.ima_log_blob.logEntry[i].template_data_len * sizeof(u_int8_t);
    }

    bytes_to_send += sizeof last;
    memcpy(to_send_data + acc, last, sizeof last);

    WAM_write(&ch_send, to_send_data, (uint32_t)bytes_to_send, false);
    fprintf(stdout, "\t\n DONE WRITING \n");
  }

  bool pcr_check_if_zeros(ESYS_CONTEXT *esys_context)
  {
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
    if (tss_r != TSS2_RC_SUCCESS)
    {
      fprintf(stderr, "Error while reading PCRs from TPM\n");
      return false;
    }

    // Go through all PCRs in each bank
    for (i = 0; i < pcr_select.count; i++)
    {
      const char *alg_name;
      if (pcr_select.pcrSelections[i].hash == TPM2_ALG_SHA1)
      {
        alg_name = malloc(strlen("sha1") * sizeof(char));
        alg_name = "sha1";
      }
      else if (pcr_select.pcrSelections[i].hash == TPM2_ALG_SHA256)
      {
        alg_name = malloc(strlen("sha256") * sizeof(char));
        alg_name = "sha256";
      }

      // Go through all PCRs in this banks
      unsigned int pcr_id;
      for (pcr_id = 0; pcr_id < pcr_select.pcrSelections[i].sizeofSelect * 8u; pcr_id++)
      {
        // skip unset pcrs (bit = 0)
        if (!(pcr_select.pcrSelections[i].pcrSelect[((pcr_id) / 8)] & (1 << ((pcr_id) % 8))))
        {
          continue;
        }

        if (vi >= pcrs.count || di >= pcrs.pcr_values[vi].count)
        {
          fprintf(stderr, "Trying to print but nothing more! di: %d, count: %d\n", di, pcrs.pcr_values[vi].count);
          return false;
        }

        // Print current PRC content (digest value)
        TPM2B_DIGEST *d = &pcrs.pcr_values[vi].digests[di];
        if (pcr_select.pcrSelections[i].hash == TPM2_ALG_SHA1)
        {
          if (memcmp(d->buffer, pcr_max, SHA_DIGEST_LENGTH))
          return false;
        }
        else if (pcr_select.pcrSelections[i].hash == TPM2_ALG_SHA256)
        {
          if (memcmp(d->buffer, pcr_max, SHA256_DIGEST_LENGTH))
          return false;
        }

        if (++di >= pcrs.pcr_values[vi].count)
        {
          di = 0;
          ++vi;
        }
      }
    }

    return true;
  }
