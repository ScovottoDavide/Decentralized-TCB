#include "PCR9Extend.h"

#define SHA1_LEN 20
#define SHA256_LEN 64

bool openAKPub(const char *path, unsigned char **akPub) {

  FILE *ak_pub = fopen(path, "r");
  if(ak_pub == NULL){
    fprintf(stderr, "Could not open file %s \n", path);
    return false;
  }

  char line[4096];
  char buff[4096];
  char h1[128], h2[128], h3[128];
  // remove the header of the AK public key
  fscanf(ak_pub, "%s %s %s", h1, h2, h3);
  strcat(h1, " ");
  strcat(h2, " ");
  strcat(h3, "\n");
  strcat(h2, h3);
  strcat(h1, h2);
  strcat(buff, h1);

  while(fscanf(ak_pub, "%s \n", line) == 1){
    if(line[0] == '-') break; // To avoid the footer of the AK public key
    strcat(line, "\n");
    strcat(buff, line);
  }

  strcat(line, " ");
  fscanf(ak_pub, "%s %s", h1, h2);
  strcat(h1, " ");
  strcat(h2, "\n");
  strcat(h1, h2);
  strcat(line, h1);
  strcat(buff, line);

  *akPub = (char *) malloc(strlen(buff)*sizeof(char));
  strncpy(*akPub, buff, strlen(buff));

  //fprintf(stderr, "%s\n", *akPub);
  fclose (ak_pub);
  return true;
}

bool computeDigest(unsigned char* akPub, const char* sha_alg, unsigned char **digest) {

  unsigned long len = strlen(akPub);
  char *local_digest;

  if(!strcmp(sha_alg, "sha1")){
    local_digest = malloc(SHA1_LEN*sizeof(char));
    SHA1(akPub, len, local_digest);
    *digest = malloc(SHA1_LEN*sizeof(char));
    strncpy(*digest, local_digest, SHA1_LEN);
  }
  else if (!strcmp(sha_alg, "sha256")){
    local_digest = malloc(SHA256_LEN*sizeof(char));
    SHA256(akPub, len, local_digest);
    *digest = malloc((SHA256_LEN)*sizeof(char));
    strncpy(*digest, local_digest, SHA256_LEN);
  } else {
    fprintf(stderr, "Algorithm %s not supported\n", sha_alg);
    return false;
  }

  return true;
}

TSS2_RC ExtendPCR9(ESYS_CONTEXT *ectx) {
  unsigned char *akPub;
  unsigned char *digest;

  bool res = openAKPub("/etc/tc/ak.pub.pem", &akPub);
  if(!res) fprintf(stderr, "Could not read AK pub\n");

  computeDigest(akPub, "sha256", &digest);
  int i;
  for(i = 0; i<strlen(digest); i++){
    printf("%02x", digest[i]);
  }

  fprintf(stderr, "%02x\n", digest);
  ESYS_TR  pcrHandle_handle = 9;
  TPML_DIGEST_VALUES digests
        = {
        .count = 1,
        .digests = {
            {
                .hashAlg = TPM2_ALG_SHA256,
                .digest = {
                    .sha256 = *digest
                }
            },
        }};

  TSS2_RC tss_r = Esys_PCR_Extend(ectx, pcrHandle_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &digests);
  if(tss_r != TSS2_RC_SUCCESS){
    fprintf(stderr, "Could not extend PCR:%d\n", pcrHandle_handle);
    exit(-1);
  }

  return tss_r;
}
