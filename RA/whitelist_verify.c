#include "whitelist_verify.h"

int computeTemplateDigest(unsigned char *template, const char *sha_alg, unsigned char **digest, int size)
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
  EVP_DigestUpdate(mdctx, template, size);
  EVP_DigestFinal_ex(mdctx, *digest, &md_len);
  EVP_MD_CTX_free(mdctx);

  return md_len;
}

int computePCR10Aggr(unsigned char *pcr_concatenated, const char *sha_alg, unsigned char **digest, int size)
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

bool loadWhitelist(FILE *fp, struct whitelist_entry *white_entries, int size)
{
  unsigned char digest[DIGEST_LEN];
  int file_path_len = 0;
  int i = 0;
  for (i = 0; i < size; i++)
  {
    fscanf(fp, "%s %d", white_entries[i].digest, &file_path_len);
    white_entries[i].digest[DIGEST_LEN] = '\0';
    white_entries[i].path = malloc(file_path_len * sizeof(char));
    fscanf(fp, "%s", white_entries[i].path);
    // fprintf(stdout, "%s %s\n", white_entries[i].digest, white_entries[i].path);
  }
  return true;
}

/* returns the index of the white_entries vector if match is found, otherwise -1 is returned */
int match_IMApath_Whitepath(const char *imaPath, const u_int32_t imaPath_len, const struct whitelist_entry *white_entries, int white_entries_size)
{
  int i;

  for (i = 0; i < white_entries_size; i++)
  {
    if (strncmp(white_entries[i].path, imaPath, imaPath_len) == 0) // match
      return i;
  }
  return -1;
}

static int read_template_data(struct event *template, FILE *fp, const struct whitelist_entry *white_entries, int white_entries_size, u_int8_t pcr_aggr[SHA256_DIGEST_LENGTH + 1])
{
  int len, is_ima_template, is_imang_template, i, k = 0;
  u_int8_t *pcr_concatenated = calloc(SHA256_DIGEST_LENGTH * 2 + 1, sizeof(u_int8_t));

  u_int8_t *entry_aggregate; 
  u_int8_t *currentTemplateMD = calloc(SHA256_DIGEST_LENGTH + 1, sizeof(u_int8_t));
  u_int8_t acc = 0;

  /* Init empty pcr */
  for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
  {
    pcr_concatenated[i] = (u_int8_t)pcr_aggr[i];
  }
  
  is_ima_template = strcmp(template->name, "ima") == 0 ? 1 : 0;
  is_imang_template = strcmp(template->name, "ima-ng") == 0 ? 1 : 0;

  if (!is_ima_template)
  {
    fread(&template->template_data_len, sizeof(u_int32_t), 1, fp);
    len = template->template_data_len;
  }
  else
  {
    template->template_data_len = SHA_DIGEST_LENGTH +
                                  TCG_EVENT_NAME_LEN_MAX + 1;
    /*
     * Read the digest only as the event name length
     * is not known in advance.
     */
    len = SHA_DIGEST_LENGTH;
  }

  template->template_data = calloc(template->template_data_len, sizeof(u_int8_t));
  entry_aggregate = calloc(template->template_data_len, sizeof(u_int8_t));

  if (template->template_data == NULL)
  {
    printf("ERROR: out of memory\n");
    return -1;
  }

  if (is_ima_template)
  { /* finish 'ima' template data read */
    u_int32_t field_len;
    fread(template->template_data, len, 1, fp);

    fread(&field_len, sizeof(u_int32_t), 1, fp);
    fread(template->template_data + SHA_DIGEST_LENGTH, field_len, 1, fp);
  }
  else if (is_imang_template)
  { /* finish 'ima-ng' template data read */
    u_int32_t field_len;
    u_int32_t field_path_len;
    u_int8_t alg_field[8];      /* sha256:\0 */
    u_int8_t alg_sha1_field[6]; /* sha1:\0 */
    u_int8_t *path_field;

    int is_sha1 = 0;

    fread(&field_len, sizeof(u_int32_t), 1, fp); /* d-ng:[uint32 little endian hash len]* */
    memcpy(entry_aggregate + acc, &field_len, sizeof field_len);
    acc += sizeof field_len;
    if (field_len != 0x28)
    {
      fread(alg_sha1_field, sizeof(u_int8_t), 6, fp);
      memcpy(entry_aggregate + acc, alg_field, sizeof alg_field);
      acc += sizeof alg_field;
      is_sha1 = 1;
      /* Here if it's a sha1 then is a violation because i'm using ima.ng sha256 */
      fread(template->template_data, sizeof(u_int8_t), SHA_DIGEST_LENGTH, fp); /* [file hash] */
      /* If violation --> 0xff instead of leaving 0x00 */
      memset(entry_aggregate + acc, 0xff, SHA_DIGEST_LENGTH);
      acc += SHA_DIGEST_LENGTH;
    }
    else
    {
      fread(alg_field, sizeof(u_int8_t), 8, fp);
      memcpy(entry_aggregate + acc, alg_field, sizeof alg_field);
      acc += sizeof alg_field;
      fread(template->template_data, sizeof(u_int8_t), SHA256_DIGEST_LENGTH, fp); /* [file hash] */
      memcpy(entry_aggregate + acc, template->template_data, SHA256_DIGEST_LENGTH);
      acc += SHA256_DIGEST_LENGTH;
    }

    fread(&field_path_len, sizeof field_path_len, 1, fp); /* n-ng:[uint32 little endian path len] */
    memcpy(entry_aggregate + acc, &field_path_len, sizeof field_path_len);
    acc += sizeof field_path_len;

    path_field = malloc(field_path_len * sizeof(u_int8_t));

    fread(path_field, sizeof(u_int8_t), field_path_len, fp); /* [file hash] */
    memcpy(entry_aggregate + acc, path_field, field_path_len);
    acc += sizeof path_field; 

    int mdTemplate;
    if(!is_sha1)
      mdTemplate = computeTemplateDigest(entry_aggregate, "sha256", &currentTemplateMD, template->template_data_len);

    k = SHA256_DIGEST_LENGTH;
    for(i=0; i<SHA256_DIGEST_LENGTH;i++){
      pcr_concatenated[k++] = currentTemplateMD[i];
    }
    int mdPCR = computePCR10Aggr(pcr_concatenated, "sha256", &pcr_aggr, SHA256_DIGEST_LENGTH*2);
    
    int entry_index = match_IMApath_Whitepath(path_field, field_path_len, white_entries, white_entries_size);

    unsigned char string_digest[DIGEST_LEN];
    int k = 0;
    if (!is_sha1)
    {
      for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
      {
        sprintf(&string_digest[i * 2], "%02x", template->template_data[i]);
      }
    }
    if (entry_index >= 0)
    {
      if (strcmp(white_entries[entry_index].digest, string_digest))
      {
        // fprintf(stdout, "State Untrusted: ");
        fprintf(stdout, "Path: %s IMA_LOG: %s Whitelist: %s\n", white_entries[entry_index].path, string_digest, white_entries[entry_index].digest);
        return -2;
      }
      else
      {
        fprintf(stdout, "OKKK Path: %s IMA_LOG: %s Whitelist: %s\n", white_entries[entry_index].path, string_digest, white_entries[entry_index].digest);
      }
    }
  }
  free(currentTemplateMD);
  free(pcr_concatenated);
  free(entry_aggregate);
  return 0;
}

int verify_PCR10_whitelist(u_int8_t *pcr10_sha1, u_int8_t *pcr10_sha256)
{
  struct event template;
  struct whitelist_entry *white_entries;
  FILE *ima_fp, *whitelist_fp;
  int num_entries = 0, i;

  ima_fp = fopen("/etc/tc/IMA_LOG_OUT", "rb");
  if (!ima_fp)
  {
    fprintf(stdout, "Could not open IMA_LOG\n");
    exit(-1);
  }

  whitelist_fp = fopen("whitelist", "rb");
  if (!whitelist_fp)
  {
    fprintf(stdout, "Could not open whitelist file\n");
    exit(-1);
  }
  
  /* Prepare stating pcr10 */
  u_int8_t *pcr_aggr;
  pcr_aggr = calloc(SHA256_DIGEST_LENGTH + 1, sizeof(u_int8_t));

  fscanf(whitelist_fp, "%d", &num_entries);
  white_entries = malloc(num_entries * sizeof(struct whitelist_entry));
  if (!white_entries)
  {
    fprintf(stdout, "OOM %d\n", num_entries);
    exit(-1);
  }

  loadWhitelist(whitelist_fp, white_entries, num_entries);
  while (fread(&template.header, sizeof template.header, 1, ima_fp))
  {
    if (template.header.name_len > TCG_EVENT_NAME_LEN_MAX)
    {
      printf("%d ERROR: event name too long!\n", template.header.name_len);
      fclose(ima_fp);
      fclose(whitelist_fp);
      exit(-1);
    }
    memset(template.name, 0, sizeof template.name);
    fread(template.name, template.header.name_len, 1, ima_fp);

    if (read_template_data(&template, ima_fp, white_entries, num_entries, pcr_aggr) == -1)
    {
      printf("\nReading of measurement entry failed\n");
      exit(-1);
    }
  }
  
  fprintf(stdout, "PCRAggr : ");
  for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
    fprintf(stdout, "%02X", pcr_aggr[i]);
  fprintf(stdout, "\n");

  if(memcmp(pcr_aggr, pcr10_sha256, SHA256_DIGEST_LENGTH) == 0){
    fprintf(stdout, "PCR10 verification successfull!\n");
  }else {
    fprintf(stdout, "PCR10 verification failed!\n");
  }

  fclose(ima_fp);
  fclose(whitelist_fp);

  return 0;
}