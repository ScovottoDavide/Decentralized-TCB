#include "whitelist_verify.h"

int computeTemplateDigest(unsigned char *template, const char *sha_alg, unsigned char *digest, int size) {
  EVP_MD_CTX *mdctx;
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
  EVP_DigestUpdate(mdctx, template, size);
  EVP_DigestFinal_ex(mdctx, digest, &md_len);
  EVP_MD_CTX_free(mdctx);

  return md_len;
}

int computePCR10Aggr(unsigned char *pcr_concatenated, const char *sha_alg, unsigned char *digest, int size) {
  EVP_MD_CTX *mdctx;
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
  EVP_DigestFinal_ex(mdctx, digest, &md_len);
  EVP_MD_CTX_free(mdctx);

  return md_len;
}

bool loadWhitelist(FILE *fp, struct whitelist_entry *white_entries, int size) {
  unsigned char digest[DIGEST_LEN];
  int file_path_len = 0;
  int i = 0;
  for (i = 0; i < size; i++) {
    fscanf(fp, "%s %d", white_entries[i].digest, &file_path_len);
    white_entries[i].digest[DIGEST_LEN] = '\0';
    white_entries[i].path = malloc(file_path_len * sizeof(char));
    fscanf(fp, "%s", white_entries[i].path);
    // fprintf(stdout, "%s %s\n", white_entries[i].digest, white_entries[i].path);
  }
  return true;
}

/* returns the index of the white_entries vector if match is found, otherwise -1 is returned */
int match_IMApath_Whitepath(const char *imaPath, const u_int32_t imaPath_len, const struct whitelist_entry *white_entries, int white_entries_size) {
  int i;
  for (i = 0; i < white_entries_size; i++) {
    if (strncmp(white_entries[i].path, imaPath, imaPath_len) == 0) // match
      return i;
  }
  return -1;
}

int read_template_data(struct event template, const struct whitelist_entry *white_entries, 
    int white_entries_size, unsigned char pcr10_sha256[SHA256_DIGEST_LENGTH + 1], unsigned char pcr10_sha1[SHA_DIGEST_LENGTH + 1], 
    VERIFICATION_RESPONSE ver_response)
{
  int len, is_ima_template, is_imang_template, i, k = 0, j;
  u_int8_t *pcr_concatenated = calloc(SHA256_DIGEST_LENGTH * 2 + 1, sizeof(u_int8_t));
  u_int8_t *pcr_concatenated_sha1 = calloc(SHA_DIGEST_LENGTH * 2 + 1, sizeof(u_int8_t));
  u_int8_t *entry_aggregate = NULL;
  u_int8_t *currentTemplateMD = calloc(SHA256_DIGEST_LENGTH + 1, sizeof(u_int8_t));
  u_int8_t *currentTemplateMD_sha1 = calloc(SHA_DIGEST_LENGTH + 1, sizeof(u_int8_t));
  u_int8_t currentEntryFileHash[SHA256_DIGEST_LENGTH + 1] = {0};
  u_int8_t acc = 0;

  /* Init empty pcr */
  for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    pcr_concatenated[i] = (u_int8_t)pcr10_sha256[i];
  }
  for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
    pcr_concatenated_sha1[i] = (u_int8_t)pcr10_sha1[i];
  }
  pcr_concatenated[SHA256_DIGEST_LENGTH * 2] = '\0';
  pcr_concatenated_sha1[SHA_DIGEST_LENGTH * 2] = '\0';
  currentTemplateMD[SHA256_DIGEST_LENGTH] = '\0';
  currentTemplateMD_sha1[SHA_DIGEST_LENGTH] = '\0';
  currentEntryFileHash[SHA256_DIGEST_LENGTH] = '\0';

  is_ima_template = strcmp(template.name, "ima") == 0 ? 1 : 0;
  is_imang_template = strcmp(template.name, "ima-ng") == 0 ? 1 : 0;

  if (is_ima_template)
  {
    template.template_data_len = SHA_DIGEST_LENGTH +
                                  TCG_EVENT_NAME_LEN_MAX + 1;
    /*
     * Read the digest only as the event name length
     * is not known in advance.
     */
    len = SHA_DIGEST_LENGTH;
  }

  entry_aggregate = calloc(template.template_data_len + 1, sizeof(u_int8_t));
  entry_aggregate[template.template_data_len] = '\0';

  if (is_imang_template)
  { /* finish 'ima-ng' template data read */
    u_int32_t field_len;
    u_int32_t field_path_len;
    u_int8_t alg_field[8];      /* sha256:\0 */
    u_int8_t alg_sha1_field[6]; /* sha1:\0 */
    u_int8_t *path_field = NULL;

    int is_sha1 = 0;

    memcpy(&field_len, template.template_data, sizeof(u_int32_t));
    memcpy(entry_aggregate + acc, &field_len, sizeof field_len);
    acc += sizeof field_len;
    if (field_len != 0x28)
    {
      memcpy(alg_sha1_field, template.template_data + acc, sizeof alg_sha1_field);
      memcpy(entry_aggregate + acc, alg_sha1_field, sizeof alg_sha1_field);
      acc += sizeof alg_sha1_field;
      is_sha1 = 1;
      
      /** This actually useless */ 
      memset(entry_aggregate + acc, 0xff, SHA_DIGEST_LENGTH); // bank I'm checking is SHA256 BANK
      acc += SHA_DIGEST_LENGTH;
    }
    else
    {
      memcpy(alg_field, template.template_data + acc, sizeof(u_int8_t) * 8);
      memcpy(entry_aggregate + acc, alg_field, sizeof alg_field);
      acc += sizeof alg_field;

      memcpy(currentEntryFileHash, template.template_data + acc, SHA256_DIGEST_LENGTH);
      currentEntryFileHash[SHA256_DIGEST_LENGTH] = '\0';
      memcpy(entry_aggregate + acc, template.template_data + acc, SHA256_DIGEST_LENGTH);
      acc += SHA256_DIGEST_LENGTH;
    }

    memcpy(&field_path_len, template.template_data + acc, sizeof field_path_len); /* n-ng:[uint32 little endian path len] */
    memcpy(entry_aggregate + acc, &field_path_len, sizeof field_path_len);
    acc += sizeof field_path_len;

    path_field = malloc(field_path_len + 1 * sizeof(u_int8_t));
    path_field[field_path_len] = '\0';

    memcpy(path_field, template.template_data + acc, sizeof(u_int8_t) * field_path_len); /* [file hash] */
    memcpy(entry_aggregate + acc, path_field, field_path_len);
    acc += sizeof path_field;

    int mdTemplate;
    if (!is_sha1) {
      mdTemplate = computeTemplateDigest(entry_aggregate, "sha256", currentTemplateMD, template.template_data_len);
      mdTemplate = computeTemplateDigest(entry_aggregate, "sha1", currentTemplateMD_sha1, template.template_data_len);
    }
      
    int mdPCR;
    if (!is_sha1) {
      k = SHA256_DIGEST_LENGTH;
      for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        pcr_concatenated[k++] = currentTemplateMD[i];
      }
      mdPCR = computePCR10Aggr(pcr_concatenated, "sha256", pcr10_sha256, SHA256_DIGEST_LENGTH * 2);
      k = SHA_DIGEST_LENGTH;
      for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        pcr_concatenated_sha1[k++] = currentTemplateMD_sha1[i];
      }
      mdPCR = computePCR10Aggr(pcr_concatenated_sha1, "sha1", pcr10_sha1, SHA_DIGEST_LENGTH * 2);
    }
    else {
      /* Here if it's a sha1 then is a violation because i'm using ima-ng sha256 */
      /* If violation --> 0xff instead of leaving 0x00 */
      k = SHA256_DIGEST_LENGTH;
      memset(pcr_concatenated + k, 0xff, SHA256_DIGEST_LENGTH);
      mdPCR = computePCR10Aggr(pcr_concatenated, "sha256", pcr10_sha256, SHA256_DIGEST_LENGTH * 2);
      k = SHA_DIGEST_LENGTH;
      memset(pcr_concatenated_sha1 + k, 0xff, SHA_DIGEST_LENGTH);
      mdPCR = computePCR10Aggr(pcr_concatenated_sha1, "sha1", pcr10_sha1, SHA_DIGEST_LENGTH * 2);
    }

    if (white_entries != NULL) {
      int entry_index = match_IMApath_Whitepath(path_field, field_path_len, white_entries, white_entries_size);

      unsigned char string_digest[DIGEST_LEN];
      int k = 0;
      if (!is_sha1) {
        for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
          sprintf(&string_digest[i * 2], "%02x", currentEntryFileHash[i]);
        }
      }
      if (entry_index >= 0) {
        if (strcmp(white_entries[entry_index].digest, string_digest)) {
          //fprintf(stdout, "State Untrusted: ");
          //fprintf(stdout, "Path: %s IMA_LOG: %s Whitelist: %s\n", white_entries[entry_index].path, string_digest, white_entries[entry_index].digest);
          if(ver_response.number_white_entries + 1 > white_entries_size) {
            //fprintf(stdout, "Expected untrusted entries limit exceeded\n");
          } else {
            ver_response.untrusted_entries[ver_response.number_white_entries].name_len = (uint16_t)field_path_len;
            ver_response.untrusted_entries[ver_response.number_white_entries].untrusted_path_name = malloc(ver_response.untrusted_entries[ver_response.number_white_entries].name_len + 1 * sizeof(char));
            strncpy(ver_response.untrusted_entries[ver_response.number_white_entries].untrusted_path_name, white_entries[entry_index].path, field_path_len);
            ver_response.untrusted_entries[ver_response.number_white_entries].untrusted_path_name[field_path_len] = '\0';
            ver_response.number_white_entries += 1;
          }
        }/*else {
          fprintf(stdout, "OKKK Path: %s IMA_LOG: %s Whitelist: %s\n", white_entries[entry_index].path, string_digest, white_entries[entry_index].digest);
        }*/
      }
    }
    //free(path_field);
  }
  /*free(currentTemplateMD); 
  free(currentTemplateMD_sha1);
  free(pcr_concatenated); 
  free(pcr_concatenated_sha1);
  free(entry_aggregate);*/
  return 0;
}

bool verify_PCR10_whitelist(unsigned char *pcr10_sha1, unsigned char *pcr10_sha256, IMA_LOG_BLOB ima_log_blob, VERIFICATION_RESPONSE ver_response) {
  struct event template;
  struct whitelist_entry *white_entries = NULL;
  FILE *whitelist_fp;
  int num_entries = 0, i;

  whitelist_fp = fopen("whitelist", "rb");
  if (!whitelist_fp) {
    fprintf(stdout, "\nNo whitelist file found! Skipping whitelist verification!\n\n");
  } else {
    fscanf(whitelist_fp, "%d", &num_entries);
    white_entries = malloc(num_entries * sizeof(struct whitelist_entry));
    if (!white_entries) {
      fprintf(stdout, "OOM %d\n", num_entries);
      exit(-1);
    }
    loadWhitelist(whitelist_fp, white_entries, num_entries);
    fclose(whitelist_fp);
  }

  ver_response.tag = 5;
  ver_response.number_white_entries = 0;
  // THE MAX NUMBER OF UNTRUSTED ENTRIES = THE NUMBER OF WHITELIST ENTRIES (WORST SCENARIO)
  ver_response.untrusted_entries = malloc(num_entries * sizeof(UNTRUSTED_PATH));

  for (i = 0; i < ima_log_blob.size; i++) {
    if (ima_log_blob.logEntry[i].header.name_len > TCG_EVENT_NAME_LEN_MAX) {
      fprintf(stdout, "%d ERROR: event name too long!\n", template.header.name_len);
      //free(white_entries);
      return false;
    }
    if (read_template_data(ima_log_blob.logEntry[i], white_entries, num_entries, pcr10_sha256, pcr10_sha1, ver_response) == -1) {
      printf("\nReading of measurement entry failed\n");
      return false;
    }
  }
    
  //free(white_entries);
  return true;
}