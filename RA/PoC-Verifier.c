#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/rand.h>

#include "tpm2_checkquote.h"
#define PORT 8080

bool pcr_get_pcr_9s(TPML_PCR_SELECTION pcr_select, tpm2_pcrs *pcrs, TPM2B_DIGEST *pcr9_sha1, TPM2B_DIGEST *pcr9_sha256);
bool openAKPub(const char *path, unsigned char **akPub);
int computeDigestEVP(unsigned char* akPub, const char* sha_alg, unsigned char **digest);
int computePCRsoftBinding(unsigned char* pcr_concatenated, const char* sha_alg, unsigned char **digest, int size);
bool PCR9_verification();

int main(int argc, char const* argv[])
{
	int sock = 0, valread;
	struct sockaddr_in serv_addr;
	unsigned char buffer[32] = { 0 };
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("\n Socket creation error \n");
		return -1;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);

	// Convert IPv4 and IPv6 addresses from text to binary form
	if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	if (connect(sock, (struct sockaddr*)&serv_addr,	sizeof(serv_addr)) < 0) {
		printf("\nConnection Failed \n");
		return -1;
	}

  	if(RAND_bytes(buffer, 32)){
    	int i;
    	//buffer[32] = '\0';
    	for(i=0; buffer[i]!='\0'; i++)
      		printf("%02x", buffer[i]);
		printf("\n");
    	send(sock, buffer, strlen(buffer), 0);
  	}

	sleep(2);

	if(!tpm2_checkquote()){
		fprintf(stderr, "Error while verifying quote!\n");
		exit(-1);
	}
	fprintf(stdout, "Quote successfully verified!!!!\n");

	if(!PCR9_verification()){
		fprintf(stderr, "PCR9 verification failed\n");
		exit(-1);
	}
  fprintf(stdout, "PCR9 verfication successfull!!!!\n");

	return 0;
}

bool pcr_get_pcr_9s(TPML_PCR_SELECTION pcr_select, tpm2_pcrs *pcrs, TPM2B_DIGEST *pcr9_sha1, TPM2B_DIGEST *pcr9_sha256) {
  UINT32 i;
  size_t vi = 0;  /* value index */
  UINT32 di = 0;  /* digest index */

  // Go through all PCRs in each bank
  for(i = 0; i < pcr_select.count; i++){
    const char *alg_name;
    if(pcr_select.pcrSelections[i].hash == TPM2_ALG_SHA1){
      alg_name = malloc(strlen("sha1")*sizeof(char));
      alg_name = "sha1";
    } else if(pcr_select.pcrSelections[i].hash == TPM2_ALG_SHA256) {
      alg_name = malloc(strlen("sha256")*sizeof(char));
      alg_name = "sha256";
    }

    // Go through all PCRs in this banks
    unsigned int pcr_id;
    for(pcr_id = 0; pcr_id < pcr_select.pcrSelections[i].sizeofSelect * 8u; pcr_id++){
      // skip unset pcrs (bit = 0)
      if(!(pcr_select.pcrSelections[i].pcrSelect[((pcr_id) / 8)] & (1 << ((pcr_id) % 8)))){
        continue;
      }

      if(vi >= pcrs->count || di >= pcrs->pcr_values[vi].count){
        fprintf(stderr, "Trying to print but nothing more! di: %d, count: %d\n", di, pcrs->pcr_values[vi].count);
        return false;
      }

      if(pcr_id == 9){
        TPM2B_DIGEST *d = &pcrs->pcr_values[vi].digests[di];
        if(pcr_select.pcrSelections[i].hash == TPM2_ALG_SHA1){
          if(!memcpy(pcr9_sha1->buffer, d->buffer, SHA_DIGEST_LENGTH))
            return false;
        }
        else if (pcr_select.pcrSelections[i].hash == TPM2_ALG_SHA256){
          if(!memcpy(pcr9_sha256->buffer, d->buffer, SHA256_DIGEST_LENGTH))
            return false;
        }
      }

      if(++di >= pcrs->pcr_values[vi].count){
        di = 0;
        ++vi;
      }
    }
  }

  return true;
}

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

int computePCRsoftBinding(unsigned char* pcr_concatenated, const char* sha_alg, unsigned char **digest, int size){
  EVP_MD_CTX*mdctx;
  const EVP_MD *md;
  unsigned int md_len, i;

  OpenSSL_add_all_digests();

  md = EVP_get_digestbyname(sha_alg);
  if (md == NULL) {
    printf("Unknown message digest %s\n", sha_alg);
    return false;
  }

  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, pcr_concatenated, size);
  EVP_DigestFinal_ex(mdctx, *digest, &md_len);
  EVP_MD_CTX_free(mdctx);

  return md_len;
}

bool PCR9_verification() {
	TPML_PCR_SELECTION pcr_select;
  tpm2_pcrs *pcrs;
  tpm2_pcrs temp_pcrs = {};
	TPM2B_DIGEST pcr9_sha1, pcr9_sha256;
	const char *file_path = "/etc/tc/pcrs.out";
  int i;

	// Read pcrs from the specified file
    if(!pcrs_from_file(file_path, &pcr_select, &temp_pcrs)){
        // Internal error log
        return false;
    }
	pcrs = &temp_pcrs;
	if(le32toh(pcr_select.count) > TPM2_NUM_PCR_BANKS){
        return false;
    }

	if(!pcr_get_pcr_9s(pcr_select, pcrs, &pcr9_sha1, &pcr9_sha256)){
		fprintf(stderr, "Could not retrieve pcr9s for verification of AK soft binding\n");
		return false;
	}

	unsigned char *akPub = NULL;
 	unsigned char *digest_sha1 = NULL;
	unsigned char *digest_sha256 = NULL;
	if(!openAKPub("/etc/tc/ak.pub.pem", &akPub)){
		fprintf(stderr, "Could not read AK pub\n");
		return false;
	}

	digest_sha1 = malloc((EVP_MAX_MD_SIZE)*sizeof(unsigned char));
	digest_sha256 = malloc((EVP_MAX_MD_SIZE)*sizeof(unsigned char));
	int md_len_sha1 = computeDigestEVP(akPub, "sha1", &digest_sha1);
  if(md_len_sha1 <= 0)
    return false;
	int md_len_sha256 = computeDigestEVP(akPub, "sha256", &digest_sha256);
  if(md_len_sha256 <= 0)
    return false;

  unsigned char *expected_PCR9sha1 = NULL;
  unsigned char *expected_PCR9sha256 = NULL;

	u_int8_t *pcr_sha1;
	pcr_sha1 = calloc((SHA_DIGEST_LENGTH*2+1), sizeof(u_int8_t));
	int k=SHA_DIGEST_LENGTH;
	for(i = 0; i < md_len_sha1; i++)
	  pcr_sha1[k++] = (u_int8_t) digest_sha1[i];
	pcr_sha1[SHA_DIGEST_LENGTH*2] = '\0';
	expected_PCR9sha1 = malloc((SHA_DIGEST_LENGTH+1)*sizeof(unsigned char));
	md_len_sha1 = computePCRsoftBinding(pcr_sha1, "sha1", &expected_PCR9sha1, SHA_DIGEST_LENGTH*2);
	if(md_len_sha1 <= 0)
	  return false;

	fprintf(stdout, "expected_PCR9sha1 : ");
	for(i = 0; i < md_len_sha1; i++)
		fprintf(stdout, "%02x", expected_PCR9sha1[i]);
	fprintf(stdout, "\n");

	if(memcmp(expected_PCR9sha1, pcr9_sha1.buffer, pcr9_sha1.size))
		return false;

	free(pcr_sha1);
	free(digest_sha1);
	free(expected_PCR9sha1);

	u_int8_t *pcr_sha256;
	pcr_sha256 = calloc(SHA256_DIGEST_LENGTH*2+1, sizeof(u_int8_t));
	k=SHA256_DIGEST_LENGTH;
  for(i = 0; i < md_len_sha256; i++)
    pcr_sha256[k++] = digest_sha256[i];
	pcr_sha256[SHA256_DIGEST_LENGTH*2] = '\0';
  expected_PCR9sha256 = malloc((SHA256_DIGEST_LENGTH)*sizeof(unsigned char));
  md_len_sha256 = computePCRsoftBinding(pcr_sha256, "sha256", &expected_PCR9sha256, SHA256_DIGEST_LENGTH*2);
  if(md_len_sha256 <= 0)
    return false;

	fprintf(stdout, "expected_PCR9sha256 : ");
  for(i = 0; i < md_len_sha256; i++)
    fprintf(stdout, "%02X", expected_PCR9sha256[i]);
  fprintf(stdout, "\n");

	if(memcmp(expected_PCR9sha256, pcr9_sha256.buffer, pcr9_sha256.size))
		return false;

	free(pcr_sha256);
	free(digest_sha256);
	free(expected_PCR9sha256);

	free(akPub);
	return true;
}
