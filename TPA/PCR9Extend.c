#include "PCR9Extend.h"

typedef struct tpm_pcr_extend_ctx tpm_pcr_extend_ctx;
struct tpm_pcr_extend_ctx {
    size_t digest_spec_len;
    tpm2_pcr_digest_spec *digest_spec;
};

bool openAKPub(const char *path, unsigned char **akPub) {

  FILE *ak_pub = fopen(path, "r");
  if(ak_pub == NULL){
    fprintf(stderr, "Could not open file %s \n", path);
    return false;
  }

  char line[4096];
  char buff[4096] = {'\0'};
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

  //printf("%s\n", *akPub);
  fclose (ak_pub);
  return true;
}

int computeDigestEVP(unsigned char* akPub, const char* sha_alg, unsigned char **digest){
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
  EVP_DigestFinal_ex(mdctx, *digest, &md_len);
  EVP_MD_CTX_free(mdctx);

  return md_len;
}

TSS2_RC ExtendPCR9(ESYS_CONTEXT *ectx, const char* halg) {
  unsigned char *akPub = NULL;
  unsigned char *digest = NULL;

  bool res = openAKPub("/etc/tc/ak.pub.pem", &akPub);
  if(!res) fprintf(stderr, "Could not read AK pub\n");

  digest = malloc((EVP_MAX_MD_SIZE)*sizeof(unsigned char));

  int md_len = computeDigestEVP(akPub, halg, &digest);
  if(md_len <= 0)
    return TSS2_ESYS_RC_BAD_VALUE;

  fflush(stdout); fflush(stderr);
  fprintf(stdout, "Digest AK (%s): ", halg);
  int i;
  for(i = 0; i<md_len; i++){
    fprintf(stdout, "%x", digest[i]);
    if(i==md_len - 1)
      fprintf(stdout, "\n");
  }
  
  UINT32 pcrHandle_handle = 9;
  TPML_DIGEST_VALUES digests;
  if(!strcmp(halg, "sha1")){
    BYTE *final_digest;
    final_digest = malloc(SHA_DIGEST_LENGTH*sizeof(BYTE));
    memcpy(final_digest, digest, SHA_DIGEST_LENGTH);
    TPML_DIGEST_VALUES tmp = 
      {
        .count = 1,
        .digests = {
            {
                .hashAlg = TPM2_ALG_SHA1,
                .digest = {
                    .sha1 = *digest
                }
            },
        }
      };
      digests = tmp;
  }else {
    BYTE *final_digest = (BYTE *) digest;
    //final_digest = malloc(SHA256_DIGEST_LENGTH*sizeof(unsigned char));
    //memcpy(final_digest, digest, SHA256_DIGEST_LENGTH);
    TPML_DIGEST_VALUES tmp = 
      {
        .count = 1,
        .digests = {
            {
                .hashAlg = TPM2_ALG_SHA256,
                .digest = {
                    .sha256 = *final_digest
                }
            },
        }
      };
      digests = tmp;
  }


  TSS2_RC tss_r = Esys_PCR_Extend(ectx, pcrHandle_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &digests);
  if(tss_r != TSS2_RC_SUCCESS){
    fprintf(stderr, "Could not extend PCR:%d\n", pcrHandle_handle);
    exit(-1);
  }

  return tss_r;
}
