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
//#include "../IMA/ima_read_writeOut_binary.h"
#define PORT 8080
#define PORT_SEND 8081

int tpm2_getCap_handles_persistent(ESYS_CONTEXT *esys_context);
void waitRARequest(char *nonce);
int sendDataToRA(TO_SEND TpaData);
bool pcr_check_if_zeros(ESYS_CONTEXT *esys_context);

int main()
{

  TSS2_RC tss_r;
  ESYS_CONTEXT *esys_context = NULL;
  TSS2_TCTI_CONTEXT *tcti_context = NULL;
  unsigned char nonce[32] = {0};
  int persistent_handles = 0, i;

  TO_SEND TpaData;

  waitRARequest(nonce); // Receive request with nonce

  TpaData.nonce_blob.tag = (u_int8_t) 0;
  TpaData.nonce_blob.size = sizeof nonce;
  memcpy(TpaData.nonce_blob.buffer, nonce, TpaData.nonce_blob.size);

  tss_r = Tss2_TctiLdr_Initialize(NULL, &tcti_context);
  if (tss_r != TSS2_RC_SUCCESS)
  {
    printf("Could not initialize tcti context\n");
    exit(-1);
  }

  tss_r = Esys_Initialize(&esys_context, tcti_context, NULL);
  if (tss_r != TSS2_RC_SUCCESS)
  {
    printf("Could not initialize esys context\n");
    exit(-1);
  }
  /**
    Assumption: Ek is at NV-Index 0x80000000, AK is at NV-Index 0x80000001
    and they are the only persistent handles in NV-RAM.
    See if optimizable!
  **/
  // Read the # of persistent handles: if 0 proceed in creating EK and AK, otherwise DO NOT
  persistent_handles = tpm2_getCap_handles_persistent(esys_context);
  if (persistent_handles < 0)
  {
    printf("Error while reading persistent handles!\n");
    exit(-1);
  }

  if (!persistent_handles)
  {
    fprintf(stdout, "Generating EK...\n");
    tss_r = tpm2_createek(esys_context);
    if (tss_r != TSS2_RC_SUCCESS)
    {
      printf("Error in tpm2_createek\n");
      exit(-1);
    }

    fprintf(stdout, "Generating AK...\n");
    tss_r = tpm2_createak(esys_context);
    if (tss_r != TSS2_RC_SUCCESS)
    {
      printf("\tError creating AK\n");
      exit(-1);
    }

    tpm2_getCap_handles_persistent(esys_context);
  }

  if (pcr_check_if_zeros(esys_context))
  {
    // Extend both
    ExtendPCR9(esys_context, "sha1");
    ExtendPCR9(esys_context, "sha256");
  }

  tss_r = tpm2_quote(esys_context, &TpaData);
  if (tss_r != TSS2_RC_SUCCESS)
  {
    printf("Error while computing quote!\n");
    exit(-1);
  }

  /** SEND DATA TO THE REMOTE ATTESTOR */
  sendDataToRA(TpaData);

  return 0;
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

void waitRARequest(char *nonce)
{
  int server_fd, new_socket, valread;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);

  // Creating socket file descriptor
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
  {
    perror("socket failed");
    exit(EXIT_FAILURE);
  }

  // Forcefully attaching socket to the port 8080
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
  {
    perror("setsockopt");
    exit(EXIT_FAILURE);
  }
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(PORT);

  // Forcefully attaching socket to the port 8080
  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
  {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }

  printf("\tWaiting for a request!\n\n");
  if (listen(server_fd, 3) < 0)
  {
    perror("listen");
    exit(EXIT_FAILURE);
  }
  if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
  {
    perror("accept");
    exit(EXIT_FAILURE);
  }

  valread = read(new_socket, nonce, 32);
  if (valread < 0 || valread > 32)
  {
    printf("Error while reading through socket!\n");
    exit(EXIT_FAILURE);
  }
  nonce[32] = '\0';
}

int sendDataToRA(TO_SEND TpaData)
{

  int sock = 0, valread, i;
  struct sockaddr_in serv_addr;
  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    printf("\n Socket creation error \n");
    return -1;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(PORT_SEND);

  // Convert IPv4 and IPv6 addresses from text to binary form
  if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0)
  {
    printf("\nInvalid address/ Address not supported \n");
    return -1;
  }

  if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
  {
    printf("\nConnection Failed \n");
    return -1;
  }

  /** NO NEED TO SEND BACK THE NONCE SINCE THE RA WILL USE THE NONCE HE GENERATED FOR THIS REQUEST
   *  ALSO IMPORTANT BECAUSE IT AVOIDS REPLAY ATTACKS IF THE RA DOES NOT DO ANY CHECKS ON THE FRESHNESS
   *  OF THE JUST RECEIVED NONCE
  */

  ssize_t sentBytes = send(sock, &TpaData.pcrs_blob.tag, sizeof(u_int8_t), 0);
  sentBytes += send(sock, &TpaData.pcrs_blob.pcr_selection, sizeof(TPML_PCR_SELECTION), 0);
  sentBytes += send(sock, &TpaData.pcrs_blob.pcrs.count, sizeof TpaData.pcrs_blob.pcrs.count, 0);
  sentBytes += send(sock, &TpaData.pcrs_blob.pcrs.pcr_values, sizeof(TPML_DIGEST)*TpaData.pcrs_blob.pcrs.count, 0);

  sentBytes += send(sock, &TpaData.sig_blob.tag, sizeof(u_int8_t), 0);
  sentBytes += send(sock, &TpaData.sig_blob.size, sizeof(u_int16_t), 0);
  sentBytes += send(sock, &TpaData.sig_blob.buffer, sizeof(u_int8_t)*TpaData.sig_blob.size, 0);

  sentBytes += send(sock, &TpaData.message_blob.tag, sizeof(u_int8_t), 0);
  sentBytes += send(sock, &TpaData.message_blob.size, sizeof(u_int16_t), 0);
  sentBytes += send(sock, &TpaData.message_blob.buffer, sizeof(u_int8_t)*TpaData.message_blob.size, 0);

  fprintf(stdout, "sentBytes = %d\n", sentBytes);
  return sentBytes;
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
