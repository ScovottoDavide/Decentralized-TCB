#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#include "tpm2_createek.h"
#include "tpm2_createak.h"
#include "PCR9Extend.h"

int tpm2_getCap_handles_persistent(ESYS_CONTEXT* esys_context);

int main() {

  TSS2_RC tss_r;
  ESYS_CONTEXT* esys_context = NULL;
  TSS2_TCTI_CONTEXT* tcti_context = NULL;

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

  ExtendPCR9(esys_context);

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
  return 1;
}
