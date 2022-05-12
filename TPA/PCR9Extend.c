#include "PCR9Extend.h"
#include "createak_util.h"

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

int tpm2_util_hex_to_byte_structure(const char *input_string, UINT16 *byte_length, BYTE *byte_buffer){
   int str_length; //if the input_string likes "1a2b...", no prefix "0x"
   int i = 0;
   if (input_string == NULL || byte_length == NULL || byte_buffer == NULL)
       return -1;
   str_length = strlen(input_string);
   if (str_length % 2)
       return -2;
   for (i = 0; i < str_length; i++) {
       if (!isxdigit(input_string[i]))
           return -3;
   }

   if (*byte_length < str_length / 2)
       return -4;

   *byte_length = str_length / 2;

   for (i = 0; i < *byte_length; i++) {
       char tmp_str[4] = { 0 };
       tmp_str[0] = input_string[i * 2];
       tmp_str[1] = input_string[i * 2 + 1];
       byte_buffer[i] = strtol(tmp_str, NULL, 16);
   }
   return 0;
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

  int loop = 0, i = 0;
  char hex_digest[(md_len*2)+1];
  for(loop=0; loop < md_len; loop++){
    sprintf((char *)(hex_digest+i), "%02x", digest[loop]);
    i+=2;
  }
  hex_digest[i++] = '\0';

  fprintf(stdout, "Digest AK (%s): %s\n", halg, hex_digest);

  TPMI_DH_PCR pcr_index;
  // get PCR id
  tpm2_util_handle_from_optarg("9", &pcr_index, TPM2_HANDLE_FLAGS_PCR);

  BYTE *digest_bytes;
  UINT16 expected_hash_size = 0;
  if(strcmp(halg, "sha1") == 0){
    expected_hash_size = SHA_DIGEST_LENGTH;
    digest_bytes = malloc(SHA_DIGEST_LENGTH*sizeof(BYTE));
  }else if(strcmp(halg, "sha256") == 0){
    expected_hash_size = SHA256_DIGEST_LENGTH;
    digest_bytes = malloc(SHA256_DIGEST_LENGTH*sizeof(BYTE));
  }

  UINT16 size = expected_hash_size;
  int rc = tpm2_util_hex_to_byte_structure(hex_digest, &size, digest_bytes);
  if(rc){
    fprintf(stderr, "Could not convert string in bytes %d\n", rc);
    return TSS2_ESYS_RC_BAD_VALUE;
  }

  if (expected_hash_size != size) {
      fprintf(stdout, "Algorithm \"%s\" expects a size of %u bytes, got: %u", halg, expected_hash_size, size);
      return TSS2_ESYS_RC_BAD_VALUE;
  }

  TPML_DIGEST_VALUES digests;
  if(!strcmp(halg, "sha1")){
    digests.count = 1;
    digests.digests->hashAlg = TPM2_ALG_SHA1;
    memcpy(digests.digests->digest.sha1, digest_bytes, size);
  }else {
    digests.count = 1;
    digests.digests->hashAlg = TPM2_ALG_SHA256;
    memcpy(digests.digests->digest.sha256, digest_bytes, size);
  }


  TSS2_RC tss_r = Esys_PCR_Extend(ectx, pcr_index, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &digests);
  if(tss_r != TSS2_RC_SUCCESS){
    fprintf(stderr, "Could not extend PCR:%d\n", pcr_index);
    exit(-1);
  }
  return tss_r;
}
