#include "whitelist_verify.h"

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

static int read_template_data(struct event *template, FILE *fp, const struct whitelist_entry *white_entries, int white_entries_size, u_int8_t pcr_aggr[SHA256_DIGEST_LENGTH*+1])
{
  int len, is_ima_template, is_imang_template, i, k = 0;
  u_int8_t *pcr_concatenated = calloc(SHA256_DIGEST_LENGTH*2 + 1, sizeof(u_int8_t));

  /* Init empty pcr */
  for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
  {
    pcr_concatenated[i] = (u_int8_t) pcr_aggr[i];
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

    if (field_len != 0x28)
    {
      fread(alg_sha1_field, sizeof(u_int8_t), 6, fp);
      is_sha1 = 1;
      fread(template->template_data, sizeof(u_int8_t), SHA_DIGEST_LENGTH, fp); /* [file hash] */
    }
    else
    {
      fread(alg_field, sizeof(u_int8_t), 8, fp);

      fread(template->template_data, sizeof(u_int8_t), SHA256_DIGEST_LENGTH, fp); /* [file hash] */
    }

    fread(&field_path_len, sizeof field_path_len, 1, fp); /* n-ng:[uint32 little endian path len] */

    path_field = malloc(field_path_len * sizeof(u_int8_t));

    fread(path_field, sizeof(u_int8_t), field_path_len, fp); /* [file hash] */

    int entry_index = match_IMApath_Whitepath(path_field, field_path_len, white_entries, white_entries_size);

    unsigned char string_digest[DIGEST_LEN];
    int k = 0;
    if (!is_sha1)
    {
      for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
      {
        sprintf(&string_digest[i * 2], "%02x", template->template_data[i]);
      }
      /*for (i = 0; i < strlen(string_digest); i++)
        fprintf(stdout, "%c", string_digest[i]);
      fprintf(stdout, "\n");*/
      k = SHA256_DIGEST_LENGTH;
      for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
      {
        pcr_concatenated[k++] = (u_int8_t) template->template_data[i]; // attach last part of concatenation
      }
      pcr_concatenated[SHA256_DIGEST_LENGTH*2] = '\0';
      for (i = 0; i < SHA256_DIGEST_LENGTH*2; i++)
        fprintf(stdout, "%02x", pcr_concatenated[i]);
      fprintf(stdout, "\n");
      int md_len = computePCR10Aggr(pcr_concatenated, "sha256", &pcr_aggr, SHA256_DIGEST_LENGTH*2-1);
      /*for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
        fprintf(stdout, "%02X", pcr_aggr[i]);
      fprintf(stdout, "\n");*/
      if (md_len < SHA256_DIGEST_LENGTH)
        return -4;
    }
    else
    {
      for (i = 0; i < SHA_DIGEST_LENGTH; i++)
      {
        sprintf(&string_digest[i * 2], "%02x", template->template_data[i]);
      }
      k = SHA_DIGEST_LENGTH;
      for (i = 0; i < SHA_DIGEST_LENGTH; i++)
      {
        pcr_concatenated[k++] = template->template_data[i]; // attach last part of concatenation
      }
      int md_len = computePCR10Aggr(pcr_concatenated, "sha256", &pcr_aggr, SHA256_DIGEST_LENGTH + SHA_DIGEST_LENGTH);
      if (md_len < SHA256_DIGEST_LENGTH)
        return -4;
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
  pcr_aggr = calloc(SHA256_DIGEST_LENGTH+1, sizeof(u_int8_t));

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

  fclose(ima_fp);
  fclose(whitelist_fp);

  return 0;
}