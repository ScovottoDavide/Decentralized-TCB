#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/rand.h>

//#include "tpm2_checkquote.h"
#include "whitelist_verify.h"
#define NONCE_LEN 32
#define PORT 8080
#define PORT_RECV 8081

void waitTPAData(TO_SEND *TpaData);
bool pcr_get_pcr_byId(TPML_PCR_SELECTION pcr_select, tpm2_pcrs *pcrs, TPM2B_DIGEST *pcr9_sha1, TPM2B_DIGEST *pcr9_sha256, int id);
bool openAKPub(const char *path, unsigned char **akPub);
int computeDigestEVP(unsigned char *akPub, const char *sha_alg, unsigned char **digest);
int computePCRsoftBinding(unsigned char *pcr_concatenated, const char *sha_alg, unsigned char **digest, int size);
bool PCR9_verification(TPM2B_DIGEST *pcr10_sha1, TPM2B_DIGEST *pcr10_sha256, PCRS_BLOB pcrs_blob);

int main(int argc, char const *argv[])
{
  int sock = 0, valread, i;
  struct sockaddr_in serv_addr;
  TO_SEND TpaData;

  TpaData.nonce_blob.tag = 0;
  TpaData.nonce_blob.size = NONCE_LEN;

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    printf("\n Socket creation error \n");
    return -1;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(PORT);

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

  if (!RAND_bytes(TpaData.nonce_blob.buffer, NONCE_LEN))
  {
    return -1;
  }
  else
  {
    TpaData.nonce_blob.buffer[NONCE_LEN] = '\0';
    for (i = 0; i < NONCE_LEN; i++)
      printf("%02x", TpaData.nonce_blob.buffer[i]);
    printf("\n");
    send(sock, TpaData.nonce_blob.buffer, NONCE_LEN, 0);
  }

  waitTPAData(&TpaData);

  if (!tpm2_checkquote(TpaData))
  {
    fprintf(stderr, "Error while verifying quote!\n");
    exit(-1);
  }
  fprintf(stdout, "Quote successfully verified!!!!\n");

  TPM2B_DIGEST pcr10_sha256, pcr10_sha1;
  // Get also pcr10 since we're reading pcrs here
  if (!PCR9_verification(&pcr10_sha1, &pcr10_sha256, TpaData.pcrs_blob))
  {
    fprintf(stderr, "PCR9 verification failed\n");
    exit(-1);
  }
  fprintf(stdout, "PCR9 verfication successfull!!!!\n");

  // PCR10 verification in whitelist verify
  verify_PCR10_whitelist(pcr10_sha1.buffer, pcr10_sha256.buffer, TpaData.ima_log_blob);

  return 0;
}

void waitTPAData(TO_SEND *TpaData)
{
  int server_fd, new_socket, valread;
  struct sockaddr_in address;
  int opt = 1, i;
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
  address.sin_port = htons(PORT_RECV);

  // Forcefully attaching socket to the port 8080
  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
  {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }

  printf("\tWaiting for TPA to send Attestation data!\n\n");
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

  fprintf(stdout, "TPA data arrived... \n\n");

  /** READ PCRS FROM SOCKET */
  valread = read(new_socket, &TpaData->pcrs_blob.tag, sizeof(u_int8_t));
  if (valread < 0 || valread > sizeof(u_int8_t))
  {
    fprintf(stdout, "Error while reading through socket!\n");
    exit(EXIT_FAILURE);
  }
  if (TpaData->pcrs_blob.tag != 3)
  {
    fprintf(stdout, "Wrong tag received for the pcrs!\n");
    exit(EXIT_FAILURE);
  }
  valread = read(new_socket, &TpaData->pcrs_blob.pcr_selection, sizeof(TPML_PCR_SELECTION));
  if (valread < 0 || valread > sizeof(TPML_PCR_SELECTION))
  {
    fprintf(stdout, "Error while reading through socket!\n");
    exit(EXIT_FAILURE);
  }

  valread = read(new_socket, &TpaData->pcrs_blob.pcrs.count, sizeof TpaData->pcrs_blob.pcrs.count);
  if (valread < 0 || valread > sizeof TpaData->pcrs_blob.pcrs.count)
  {
    fprintf(stdout, "Error while reading through socket!\n");
    exit(EXIT_FAILURE);
  }

  valread = read(new_socket, &TpaData->pcrs_blob.pcrs.pcr_values, sizeof(TPML_DIGEST) * TpaData->pcrs_blob.pcrs.count);
  if (valread < 0 || valread > sizeof(TPML_DIGEST) * TpaData->pcrs_blob.pcrs.count)
  {
    fprintf(stdout, "Error while reading through socket!\n");
    exit(EXIT_FAILURE);
  }
  /** END OF READING PCRS */

  /** READ SIGNATURE FROM SOCKET */
  valread = read(new_socket, &TpaData->sig_blob.tag, sizeof(u_int8_t));
  if (valread < 0 || valread > sizeof(u_int8_t))
  {
    fprintf(stdout, "Error while reading through socket!\n");
    exit(EXIT_FAILURE);
  }
  if (TpaData->sig_blob.tag != 1)
  {
    fprintf(stdout, "Wrong tag received for the signature!\n");
    exit(EXIT_FAILURE);
  }
  valread = read(new_socket, &TpaData->sig_blob.size, sizeof(u_int16_t));
  if (valread < 0 || valread > sizeof(u_int16_t))
  {
    fprintf(stdout, "Error while reading through socket!\n");
    exit(EXIT_FAILURE);
  }

  TpaData->sig_blob.buffer = malloc(TpaData->sig_blob.size * sizeof(u_int8_t));

  valread = read(new_socket, TpaData->sig_blob.buffer, sizeof(u_int8_t) * TpaData->sig_blob.size);
  if (valread < 0 || valread > sizeof(u_int8_t) * TpaData->sig_blob.size)
  {
    fprintf(stdout, "Error while reading through socket!\n");
    exit(EXIT_FAILURE);
  }
  /** END OF READING SIGNATURE */

  /** READ QUOTE FROM SOCKET */
  valread = read(new_socket, &TpaData->message_blob.tag, sizeof(u_int8_t));
  if (valread < 0 || valread > sizeof(u_int8_t))
  {
    fprintf(stdout, "Error while reading through socket!\n");
    exit(EXIT_FAILURE);
  }
  if (TpaData->message_blob.tag != 2)
  {
    fprintf(stdout, "Wrong tag received for the quote!\n");
    exit(EXIT_FAILURE);
  }
  valread = read(new_socket, &TpaData->message_blob.size, sizeof(u_int16_t));
  if (valread < 0 || valread > sizeof(u_int16_t))
  {
    fprintf(stdout, "Error while reading through socket!\n");
    exit(EXIT_FAILURE);
  }

  TpaData->message_blob.buffer = malloc(TpaData->message_blob.size * sizeof(u_int8_t));
  valread = read(new_socket, TpaData->message_blob.buffer, TpaData->message_blob.size);
  if (valread < 0 || valread > TpaData->message_blob.size)
  {
    fprintf(stdout, "Error while reading through socket!\n");
    exit(EXIT_FAILURE);
  }
  /** END OF READING QUOTE */

  /** READ IMA LOG */
  valread = read(new_socket, &TpaData->ima_log_blob.tag, sizeof(u_int8_t));
  if (valread < 0 || valread > sizeof(u_int8_t))
  {
    fprintf(stdout, "Error while reading through socket!\n");
    exit(EXIT_FAILURE);
  }
  if (TpaData->ima_log_blob.tag != 4)
  {
    fprintf(stdout, "Wrong tag received for the quote!\n");
    exit(EXIT_FAILURE);
  }
  valread = read(new_socket, &TpaData->ima_log_blob.size, sizeof(u_int16_t));
  if (valread < 0 || valread > sizeof(u_int16_t))
  {
    fprintf(stdout, "Error while reading through socket!\n");
    exit(EXIT_FAILURE);
  }
  TpaData->ima_log_blob.logEntry = malloc(TpaData->ima_log_blob.size * sizeof(struct event));
  for (i = 0; i < TpaData->ima_log_blob.size; i++)
  {
    valread = read(new_socket, &TpaData->ima_log_blob.logEntry[i].header, sizeof TpaData->ima_log_blob.logEntry[i].header);
    if (valread < 0 || valread > sizeof TpaData->ima_log_blob.logEntry[i].header)
    {
      fprintf(stdout, "Error while reading through socket!\n");
      exit(EXIT_FAILURE);
    }
    valread = read(new_socket, TpaData->ima_log_blob.logEntry[i].name, TpaData->ima_log_blob.logEntry[i].header.name_len * sizeof(char));
    if (valread < 0 || valread > TpaData->ima_log_blob.logEntry[i].header.name_len * sizeof(char))
    {
      fprintf(stdout, "Error while reading through socket!\n");
      exit(EXIT_FAILURE);
    }
    valread = read(new_socket, &TpaData->ima_log_blob.logEntry[i].template_data_len, sizeof(u_int32_t));
    if (valread < 0 || valread > sizeof(u_int32_t))
    {
      fprintf(stdout, "Error while reading through socket!\n");
      exit(EXIT_FAILURE);
    }

    TpaData->ima_log_blob.logEntry[i].template_data = malloc(TpaData->ima_log_blob.logEntry[i].template_data_len * sizeof(u_int8_t));
    valread = read(new_socket, TpaData->ima_log_blob.logEntry[i].template_data, TpaData->ima_log_blob.logEntry[i].template_data_len * sizeof(u_int8_t));
    if (valread < 0 || valread > TpaData->ima_log_blob.logEntry[i].template_data_len * sizeof(u_int8_t))
    {
      fprintf(stdout, "Error while reading through socket 111!\n");
      exit(EXIT_FAILURE);
    }
  }
  /** END OF READ IMA LOG */
}

bool pcr_get_pcr_byId(TPML_PCR_SELECTION pcr_select, tpm2_pcrs *pcrs, TPM2B_DIGEST *pcr9_sha1, TPM2B_DIGEST *pcr9_sha256, int id)
{
  UINT32 i;
  size_t vi = 0; /* value index */
  UINT32 di = 0; /* digest index */
  const char *alg_name;
  TPM2B_DIGEST *d;

  // Go through all PCRs in each bank
  for (i = 0; i < pcr_select.count; i++)
  {
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

      if (vi >= pcrs->count || di >= pcrs->pcr_values[vi].count)
      {
        fprintf(stderr, "Trying to print but nothing more! di: %d, count: %d\n", di, pcrs->pcr_values[vi].count);
        return false;
      }

      if (pcr_id == id)
      {
        d = &pcrs->pcr_values[vi].digests[di];
        if (pcr_select.pcrSelections[i].hash == TPM2_ALG_SHA1)
        {
          if (!memcpy(pcr9_sha1->buffer, d->buffer, SHA_DIGEST_LENGTH))
          {
            goto out;
          }
        }
        else if (pcr_select.pcrSelections[i].hash == TPM2_ALG_SHA256)
        {
          if (!memcpy(pcr9_sha256->buffer, d->buffer, SHA256_DIGEST_LENGTH))
          {
            goto out;
          }
        }
      }

      if (++di >= pcrs->pcr_values[vi].count)
      {
        di = 0;
        ++vi;
      }
    }
  }

  return true;
out:
  free(d);
  return false;
}

bool openAKPub(const char *path, unsigned char **akPub)
{

  FILE *ak_pub = fopen(path, "r");
  if (ak_pub == NULL)
  {
    fprintf(stderr, "Could not open file %s \n", path);
    return false;
  }

  char *line = malloc(4096 * sizeof(char));
  char *buff = malloc(4096 * sizeof(char));
  char h1[128], h2[128], h3[128];
  // remove the header of the AK public key
  fscanf(ak_pub, "%s %s %s", h1, h2, h3);
  strcat(h1, " ");
  strcat(h2, " ");
  strcat(h3, "\n");
  strcat(h2, h3);
  strcat(h1, h2);
  strcat(buff, h1);

  while (fscanf(ak_pub, "%s \n", line) == 1)
  {
    if (line[0] == '-')
      break; // To avoid the footer of the AK public key
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

  *akPub = (char *)malloc(strlen(buff) * sizeof(char));
  strncpy(*akPub, buff, strlen(buff));

  // printf("%s\n", *akPub);
  fclose(ak_pub);
  free(line);
  free(buff);
  return true;
}

int computeDigestEVP(unsigned char *akPub, const char *sha_alg, unsigned char **digest)
{
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  unsigned int md_len, i;

  OpenSSL_add_all_digests();

  md = EVP_get_digestbyname(sha_alg);
  if (md == NULL)
  {
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

int computePCRsoftBinding(unsigned char *pcr_concatenated, const char *sha_alg, unsigned char **digest, int size)
{
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  unsigned int md_len, i;

  OpenSSL_add_all_digests();

  md = EVP_get_digestbyname(sha_alg);
  if (md == NULL)
  {
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

bool PCR9_verification(TPM2B_DIGEST *pcr10_sha1, TPM2B_DIGEST *pcr10_sha256, PCRS_BLOB pcrs_blob)
{
  TPML_PCR_SELECTION pcr_select;
  tpm2_pcrs *pcrs;
  tpm2_pcrs temp_pcrs = {};
  TPM2B_DIGEST pcr9_sha1, pcr9_sha256;
  int i;

  // Get pcrs from the received pcrs blob
  pcr_select = pcrs_blob.pcr_selection;
  pcrs = &pcrs_blob.pcrs;
  if (le32toh(pcr_select.count) > TPM2_NUM_PCR_BANKS)
  {
    return false;
  }

  if (!pcr_get_pcr_byId(pcr_select, pcrs, &pcr9_sha1, &pcr9_sha256, 9))
  {
    fprintf(stderr, "Could not retrieve pcr9s for verification of AK soft binding\n");
    return false;
  }

  if (!pcr_get_pcr_byId(pcr_select, pcrs, pcr10_sha1, pcr10_sha256, 10))
  {
    fprintf(stderr, "Could not retrieve PCR10\n");
    return false;
  }

  unsigned char *akPub = NULL;
  unsigned char *digest_sha1 = NULL;
  unsigned char *digest_sha256 = NULL;
  if (!openAKPub("/etc/tc/ak.pub.pem", &akPub))
  {
    fprintf(stderr, "Could not read AK pub\n");
    return false;
  }

  digest_sha1 = malloc((EVP_MAX_MD_SIZE) * sizeof(unsigned char));
  digest_sha256 = malloc((EVP_MAX_MD_SIZE) * sizeof(unsigned char));
  int md_len_sha1 = computeDigestEVP(akPub, "sha1", &digest_sha1);
  if (md_len_sha1 <= 0)
    return false;
  int md_len_sha256 = computeDigestEVP(akPub, "sha256", &digest_sha256);
  if (md_len_sha256 <= 0)
    return false;

  unsigned char *expected_PCR9sha1 = NULL;
  unsigned char *expected_PCR9sha256 = NULL;

  u_int8_t *pcr_sha1;
  pcr_sha1 = calloc((SHA_DIGEST_LENGTH * 2 + 1), sizeof(u_int8_t));
  int k = SHA_DIGEST_LENGTH;
  for (i = 0; i < md_len_sha1; i++)
    pcr_sha1[k++] = (u_int8_t)digest_sha1[i];
  pcr_sha1[SHA_DIGEST_LENGTH * 2] = '\0';
  expected_PCR9sha1 = malloc((SHA_DIGEST_LENGTH + 1) * sizeof(unsigned char));
  md_len_sha1 = computePCRsoftBinding(pcr_sha1, "sha1", &expected_PCR9sha1, SHA_DIGEST_LENGTH * 2);
  if (md_len_sha1 <= 0)
    return false;

  fprintf(stdout, "expected_PCR9sha1 : ");
  for (i = 0; i < md_len_sha1; i++)
    fprintf(stdout, "%02X", expected_PCR9sha1[i]);
  fprintf(stdout, "\n");
  for (i = 0; i < md_len_sha1; i++)
  {
    if (pcr9_sha1.buffer[i] != expected_PCR9sha1[i])
      return false;
  }

  free(pcr_sha1);
  free(digest_sha1);
  free(expected_PCR9sha1);

  u_int8_t *pcr_sha256;
  pcr_sha256 = calloc(SHA256_DIGEST_LENGTH * 2 + 1, sizeof(u_int8_t));
  k = SHA256_DIGEST_LENGTH;
  for (i = 0; i < md_len_sha256; i++)
  {
    pcr_sha256[k++] = digest_sha256[i];
  }

  pcr_sha256[SHA256_DIGEST_LENGTH * 2] = '\0';
  expected_PCR9sha256 = malloc((SHA256_DIGEST_LENGTH) * sizeof(unsigned char));
  md_len_sha256 = computePCRsoftBinding(pcr_sha256, "sha256", &expected_PCR9sha256, SHA256_DIGEST_LENGTH * 2);
  if (md_len_sha256 <= 0)
    return false;

  fprintf(stdout, "expected_PCR9sha256 : ");
  for (i = 0; i < md_len_sha256; i++)
    fprintf(stdout, "%02X", expected_PCR9sha256[i]);
  fprintf(stdout, "\n");

  for (i = 0; i < md_len_sha256; i++)
  {
    if (pcr9_sha256.buffer[i] != expected_PCR9sha256[i])
      return false;
  }

  free(pcr_sha256);
  free(digest_sha256);
  free(expected_PCR9sha256);

  free(akPub);
  return true;
}
