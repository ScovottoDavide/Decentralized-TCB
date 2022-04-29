#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#include "tpm2_createek.h"
#include "tpm2_createak.h"
#include "PCR9Extend.h"
#define PORT 8080

int tpm2_getCap_handles_persistent(ESYS_CONTEXT* esys_context);
void waitRARequest(char *nonce);

int main() {

  TSS2_RC tss_r;
  ESYS_CONTEXT* esys_context = NULL;
  TSS2_TCTI_CONTEXT* tcti_context = NULL;
  unsigned char nonce[32] = { 0 };
  int persistent_handles = 0;

  waitRARequest(nonce); // Receive request with nonce

  /**
    Assumption: Ek is at NV-Index 0x80000000, AK is at NV-Index 0x80000001
    and they are the only persistent handles in NV-RAM.
    See if optimizable!
  **/
  // Read the # of persistent handles: if 0 proceed in creating EK and AK, otherwise DO NOT
  persistent_handles = tpm2_getCap_handles_persistent(esys_context);

  if(!persistent_handles){
    tss_r = Tss2_TctiLdr_Initialize(getenv("TPM2TOOLS_TCTI"), &tcti_context);
    if(tss_r != TSS2_RC_SUCCESS){
      printf("Could not initialize tcti context\n");
      exit(-1);
    }

    tss_r = Esys_Initialize(&esys_context, tcti_context, NULL);
    if(tss_r != TSS2_RC_SUCCESS){
      printf("Could not initialize esys context\n");
      exit(-1);
    }

    TSS2_TCTI_CONTEXT* tmp = NULL;
    tss_r = Esys_GetTcti(esys_context, &tmp);
    if(tss_r != TSS2_RC_SUCCESS){
      printf("Could not get tcti context\n");
      exit(-1);
    }

    fprintf(stderr, "Generating EK...\n");
    tss_r = tpm2_createek(esys_context);
    if(tss_r != TSS2_RC_SUCCESS){
      printf("Error in tpm2_createek\n");
      exit(-1);
    }

    fprintf(stderr, "Generating AK...\n");
    tss_r = tpm2_createak(esys_context);
    if(tss_r != TSS2_RC_SUCCESS){
      printf("\tError creating AK\n");
      exit(-1);
    }

    tpm2_getCap_handles_persistent(esys_context);

    ExtendPCR9(esys_context, "sha256");
  }else {
    printf("%d\n", nonce);
  }

  return 0;
}

int tpm2_getCap_handles_persistent(ESYS_CONTEXT* esys_context){
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
  if(tss_r != TSS2_RC_SUCCESS){
    printf("Error while reading persistent handles\n");
    return -1;
  }
  int i = 0;
  for(i=0; i<capabilityData->data.handles.count; i++){
    printf("Persistent Handle: 0x%X\n", capabilityData->data.handles.handle[i]);
  }
  return capabilityData->data.handles.count;
}

void waitRARequest(char *nonce){
  int server_fd, new_socket, valread;
	struct sockaddr_in address;
	int opt = 1;
	int addrlen = sizeof(address);

  // Creating socket file descriptor
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	// Forcefully attaching socket to the port 8080
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(PORT);

  // Forcefully attaching socket to the port 8080
	if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
  }

	if (listen(server_fd, 3) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}
	if ((new_socket	= accept(server_fd, (struct sockaddr*)&address,(socklen_t*)&addrlen)) < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

  valread = read(new_socket, nonce, 32);
  int i;
  for(i=0; i<strlen(nonce); i++)
    printf("%c", nonce[i]);
}
