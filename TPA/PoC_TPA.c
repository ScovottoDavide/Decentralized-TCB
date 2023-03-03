#include "all_util.h"
#include "tpm2_createek.h"
#include "tpm2_createak.h"
#include "tpm2_quote.h"
#include "PCR9Extend.h"

#define BILLION  1000000000L;

int my_gets_avoid_bufferoverflow(char *buffer, size_t buffer_len);
void PoC_TPA(void *input);
void PoC_TPA_init(void *input);
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
  pthread_t th_tpa, th_menu, th_tpa_init;

  if(argc == 2) {
    if(strcmp("--help", argv[1]) == 0){
      fprintf(stdout, "Supported commands:\n");
      fprintf(stdout, "1. init --> Initialize TPM configuration: sudo ./PoC_TPA [path where 'index' file is] init\n");
      fprintf(stdout, "1. run --> Execute the Trusted Platform Agent: sudo ./PoC_TPA [path where 'index' file is] run\n");
      goto exit;
    } else if(strcmp("init", argv[1]) == 0){
      pthread_create(&th_tpa_init, NULL, (void *)&PoC_TPA_init, NULL);    
      pthread_join(th_tpa_init, NULL);
      goto exit;
    } else {
      fprintf(stdout, "For help --> ./PoC_TPA --help\n");
      goto exit;
    }
  }

  if(argc == 3) {
    if(strcmp("run", argv[2]) == 0) {
      pthread_create(&th_tpa, NULL, (void *)&PoC_TPA, (void *) argv[1]);
      pthread_create(&th_menu, NULL, (void *)&menu, NULL);

      pthread_join(th_tpa, NULL);
      pthread_join(th_menu, NULL);
      goto exit;
    }
    else {
      fprintf(stdout, "Unknown command!\n");
      fprintf(stdout, "For help --> ./PoC_TPA --help\n");
    }
  }

  if(argc > 3 || argc < 2) {
    fprintf(stdout, "Wrong usage!\n");
    fprintf(stdout, "For help --> ./PoC_TPA --help\n");
  }

exit:
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

void PoC_TPA_init(void *input) {
  uint16_t ek_handle[HANDLE_SIZE], ak_handle[HANDLE_SIZE];

  if(!initialize_tpm(ek_handle, ak_handle)) {
    fprintf(stdout, "Could not initialize TPM conf\n");
    return ;
  }
  return ;
}

void PoC_TPA(void *input) {
  char *file_index_path_name = ((char *)input);
  struct timespec start, stop, delta;
  double accum;

  // TPM
  TSS2_RC tss_r;
  ESYS_CONTEXT *esys_context = NULL;
  TSS2_TCTI_CONTEXT *tcti_context = NULL;
  int persistent_handles = 0, i, ret = 0;
  TO_SEND TpaData;
  ssize_t imaLogBytesSize = 0;
  uint16_t ek_handle[HANDLE_SIZE], ak_handle[HANDLE_SIZE];

  // WAM
  uint8_t mykey[]="supersecretkeyforencryptionalby";
	WAM_channel ch_read_hearbeat, ch_send, ch_send_AK_Whitelist;
	WAM_AuthCtx a; a.type = AUTHS_NONE;
	WAM_Key k; k.data = mykey; k.data_len = (uint16_t) strlen((char*)mykey);
	uint8_t nonce[32];
	uint32_t expected_size = 32, fixed_nonce_size = 32;
	uint8_t  printed = 0;
  IOTA_Index heartBeat_index, write_index, write_index_AK_Whitelist;
  FILE *index_file;

  if(!initialize_tpm(ek_handle, ak_handle)) {
    fprintf(stdout, "Could not initialize TPM conf\n");
    return ;
  }

	IOTA_Endpoint privatenet = {.hostname = "130.192.86.15\0",
							 .port = 14000,
							 .tls = false};

  index_file = fopen(file_index_path_name, "r");
  if(index_file == NULL){
    fprintf(stdout, "Cannot open file\n");
    return ;
  }
  get_Index_from_file(index_file, &heartBeat_index, &write_index, &write_index_AK_Whitelist);
  fclose(index_file);
	
  // set read index of heatbeat
  WAM_init_channel(&ch_read_hearbeat, 1, &privatenet, &k, &a);
	set_channel_index_read(&ch_read_hearbeat, heartBeat_index.index);
  // set write index for the AkPub
  WAM_init_channel(&ch_send_AK_Whitelist, 1, &privatenet, &k, &a);
  set_channel_index_write(&ch_send_AK_Whitelist, write_index_AK_Whitelist);
  // Set write index for the quote 
  WAM_init_channel(&ch_send, 1, &privatenet, &k, &a);
  set_channel_index_write(&ch_send, write_index);

  if(!send_AK_Whitelist_WAM(&ch_send_AK_Whitelist, &TpaData)) {
    fprintf(stdout, "Could not write AK-Whitelist pub on tangle\n");
    return ;
  }
  fprintf(stdout, "AK-Whitelist published on tangle\n");

	while(1){
    if(!printed){
      fprintf(stdout, "Waiting nonce... \n");
      printed = 1;
    }
    ret = WAM_read(&ch_read_hearbeat, nonce, &fixed_nonce_size);
    if(!ret){
      fprintf(stdout, "Nonce #%d\n", expected_size / 32);
      if(ch_read_hearbeat.recv_bytes == expected_size){
        expected_size+=fixed_nonce_size;
        printed = 0;

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
        if (pcr_check_if_zeros(esys_context)) {
          // Extend both
          ExtendPCR9(esys_context, "sha1");
          fprintf(stdout, "PCR9 sha1 extended\n");
          ExtendPCR9(esys_context, "sha256");
          fprintf(stdout, "PCR9 sha256 extended\n");
        }

        tss_r = tpm2_quote(esys_context, &TpaData, imaLogBytesSize, ak_handle);
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

        if( clock_gettime(CLOCK_REALTIME, &stop) == -1 ) {
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
    } else if(ret != WAM_NOT_FOUND){
      fprintf(stdout, "Error while reading ret=%d\n", ret);
    }
    pthread_mutex_lock(&menuLock); // Lock a mutex for heartBeat_Status
    if(tpa_status == 1){ // stop
      fprintf(stdout, "TPA Stopped\n");
      pthread_mutex_unlock(&menuLock); // Unlock a mutex for heartBeat_Status
      goto end;
    }
    pthread_mutex_unlock(&menuLock); // Unlock a mutex for heartBeat_Status
  }

end:
  free(TpaData.ak_digest_blob.buffer);
  for(i = 0; i < TpaData.ima_log_blob.size; i++)
    free(TpaData.ima_log_blob.logEntry[i].template_data);
  if(TpaData.ima_log_blob.size > 0)
    free(TpaData.ima_log_blob.logEntry);
  return ;
}