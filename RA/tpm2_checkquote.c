#include "tpm2_checkquote.h"

typedef struct tpm2_verifysig_ctx tpm2_verifysig_ctx;
struct tpm2_verifysig_ctx
{
  TPMI_ALG_HASH halg;
  TPM2B_DIGEST msg_hash;
  TPM2B_DIGEST pcr_hash;
  TPMS_ATTEST attest;
  TPM2B_DATA extra_data;
  TPM2B_MAX_BUFFER signature;
  const char *pubkey_file_path;
  tpm2_loaded_object key_context_object;
};

static tpm2_verifysig_ctx ctx = {
    .halg = TPM2_ALG_SHA256,
    .msg_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer),
    .pcr_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer),
};

bool files_get_file_size(FILE *fp, unsigned long *file_size, const char *path)
{

  long current = ftell(fp);
  if (current < 0)
  {
    if (path)
    {
      fprintf(stderr, "Error getting current file offset for file \"%s\"", path);
    }
    return false;
  }

  int rc = fseek(fp, 0, SEEK_END);
  if (rc < 0)
  {
    if (path)
    {
      fprintf(stderr, "Error seeking to end of file \"%s\"", path);
    }
    return false;
  }

  long size = ftell(fp);
  if (size < 0)
  {
    if (path)
    {
      fprintf(stderr, "ftell on file \"%s\" failed", path);
    }
    return false;
  }

  rc = fseek(fp, current, SEEK_SET);
  if (rc < 0)
  {
    if (path)
    {
      fprintf(stderr, "Cannot restore initial seek position on file \"%s\"", path);
    }
    return false;
  }

  /* size cannot be negative at this point */
  *file_size = (unsigned long)size;
  return true;
}

bool read_nonce_from_file(const char *input, UINT16 *len, BYTE *buffer)
{
  FILE *f = fopen(input, "rb");
  if (!f)
  {
    fprintf(stderr, "Could not open %s file\n", input);
    return false;
  }

  unsigned long file_size;
  bool res = files_get_file_size(f, &file_size, input);
  if (!res)
    return false;

  // fprintf(stdout, "filesize: %d\n", file_size);
  if (file_size > *len)
  {
    fprintf(stderr, "File size is greater than buffer capability\n");
    return false;
  }

  *len = file_size;
  size_t count = 0;
  do
  {
    count += fread(&buffer[count], 1, *len - count, f);
  } while (count < *len && !feof(f));

  if (*len < file_size)
  {
    fprintf(stderr, "Could not read any data from file!\n");
    return false;
  }
  // fprintf(stdout, "1: %s %d\n", buffer, strlen(buffer));
  fclose(f);
  return true;
}

TPM2B_ATTEST *message_from_file(const char *msg_file_path)
{
  unsigned long size;

  FILE *f = fopen(msg_file_path, "rb");
  if (!f)
  {
    fprintf(stderr, "Could not open %s file\n", msg_file_path);
    return false;
  }
  bool res = files_get_file_size(f, &size, msg_file_path);
  if (!res || !size)
  {
    fprintf(stderr, "Could not get \"%s\" size\n", msg_file_path);
    fclose(f);
    return NULL;
  }
  fclose(f);

  TPM2B_ATTEST *msg = (TPM2B_ATTEST *)calloc(1, sizeof(TPM2B_ATTEST) + size);
  if (!msg)
  {
    fprintf(stderr, "OOM\n");
    return NULL;
  }

  UINT16 tpm = msg->size = size;
  if (!read_nonce_from_file(msg_file_path, &tpm, msg->attestationData))
  {
    free(msg);
    return NULL;
  }
  return msg;
}

bool tpm2_load_signature_from_path(const char *path, TPM2B_MAX_BUFFER *signature)
{
  signature->size = sizeof(signature->buffer);

  // this case is not the nonce but the signature
  return read_nonce_from_file(path, &signature->size, signature->buffer);
}

bool parse_selection_data_from_file(FILE *pcr_input, TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs)
{

  // Read pcr_selection from pcrs file
  if (fread(pcr_select, sizeof(TPML_PCR_SELECTION), 1, pcr_input) != 1)
  {
    fprintf(stderr, "Failed to read PCR selection from pcrs file\n");
    return false;
  }

  // Read how many pcrs have to be read
  if (fread((&pcrs->count), sizeof(UINT32), 1, pcr_input) != 1)
  {
    fprintf(stderr, "Cannot read PCR header (number of pcrs to read)\n");
    return false;
  }

  // Check the number of pcrs to read don't exceed the MAX number of pcrs that one can read
  if (le64toh(pcrs->count) > ARRAY_LEN(pcrs->pcr_values))
  {
    fprintf(stderr, "PCR count greater than allowed!\n");
    return false;
  }

  size_t i;
  for (i = 0; i < le64toh(pcrs->count); i++)
  {
    if (fread(&pcrs->pcr_values[i], sizeof(TPML_DIGEST), 1, pcr_input) != 1)
    {
      fprintf(stderr, "Failed to rtead PCR digest from file\n");
      return false;
    }
  }
  return true;
}

bool pcrs_from_file(const char *pcr_file_path, TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs)
{
  unsigned long size;

  FILE *pcr_file_pt = fopen(pcr_file_path, "rb");
  if (!pcr_file_pt)
  {
    fprintf(stderr, "Could not open pcrs file \n");
    return false;
  }

  if (!files_get_file_size(pcr_file_pt, &size, pcr_file_path))
  {
    fclose(pcr_file_pt);
    return false;
  }

  if (!size)
  {
    fprintf(stderr, "The pcr file is empty!\n");
    fclose(pcr_file_pt);
    return false;
  }

  // just get all the pcrs passed in the file without parsing it with client specified selection
  if (!parse_selection_data_from_file(pcr_file_pt, pcr_select, pcrs))
  {
    fclose(pcr_file_pt);
    return false;
  }

  fclose(pcr_file_pt);
  return true;
}

bool tpm2_openssl_hash_pcr_banks(TPMI_ALG_HASH hash_alg, TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs, TPM2B_DIGEST *digest)
{
  UINT32 vi = 0, di = 0, i;

  if (hash_alg != TPM2_ALG_SHA256)
  {
    fprintf(stderr, "Wrong HashAlgo\n");
    return false;
  }

  const EVP_MD *md = EVP_sha256(); // ctx.sig_hash_algorithm = TPM2_ALG_SHA256
  if (!md)
    return false;

  EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
  if (!mdctx)
    return false;

  int res = EVP_DigestInit_ex(mdctx, md, NULL);
  if (!res)
  {
    EVP_MD_CTX_destroy(mdctx);
    return false;
  }

  // Loop through all PCR/hash banks
  for (i = 0; i < pcr_select->count; i++)
  {

    // Loop through all PCRs in this bank
    unsigned int pcr_id;
    for (pcr_id = 0; pcr_id < pcr_select->pcrSelections[i].sizeofSelect * 8u; pcr_id++)
    {
      // skip unset pcrs (bit = 0)
      if (!(pcr_select->pcrSelections[i].pcrSelect[((pcr_id) / 8)] & (1 << ((pcr_id) % 8))))
      {
        continue;
      }

      if (vi >= pcrs->count || di >= pcrs->pcr_values[vi].count)
      {
        fprintf(stderr, "Trying to print but nothing more! di: %d, count: %d\n", di, pcrs->pcr_values[vi].count);
        return false;
      }

      // Update running digest (to compare with quote)
      TPM2B_DIGEST *b = &pcrs->pcr_values[vi].digests[di];
      res = EVP_DigestUpdate(mdctx, b->buffer, b->size);
      if (!res)
      {
        EVP_MD_CTX_destroy(mdctx);
        return false;
      }

      if (++di < pcrs->pcr_values[vi].count)
        continue;
      di = 0;
      if (++vi < pcrs->count)
        continue;
    }
  }

  // Finalize running digest
  unsigned size = EVP_MD_size(md);
  res = EVP_DigestFinal_ex(mdctx, digest->buffer, &size);
  if (!res)
  {
    EVP_MD_CTX_destroy(mdctx);
    return false;
  }

  digest->size = size;
  EVP_MD_CTX_destroy(mdctx);
  return true;
}

bool pcr_print(TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs)
{
  UINT32 i;
  size_t vi = 0; /* value index */
  UINT32 di = 0; /* digest index */

  fprintf(stdout, "pcrs: \n");
  // Go through all PCRs in each bank
  for (i = 0; i < pcr_select->count; i++)
  {
    const char *alg_name;
    if (pcr_select->pcrSelections[i].hash == TPM2_ALG_SHA1)
    {
      alg_name = malloc(strlen("sha1") * sizeof(char));
      alg_name = "sha1";
    }
    else if (pcr_select->pcrSelections[i].hash == TPM2_ALG_SHA256)
    {
      alg_name = malloc(strlen("sha256") * sizeof(char));
      alg_name = "sha256";
    }

    fprintf(stdout, "  %s\n", alg_name);
    // Go through all PCRs in this banks
    unsigned int pcr_id;
    for (pcr_id = 0; pcr_id < pcr_select->pcrSelections[i].sizeofSelect * 8u; pcr_id++)
    {
      // skip unset pcrs (bit = 0)
      if (!(pcr_select->pcrSelections[i].pcrSelect[((pcr_id) / 8)] & (1 << ((pcr_id) % 8))))
      {
        continue;
      }

      if (vi >= pcrs->count || di >= pcrs->pcr_values[vi].count)
      {
        fprintf(stderr, "Trying to print but nothing more! di: %d, count: %d\n", di, pcrs->pcr_values[vi].count);
        return false;
      }

      // Print PCR ID
      fprintf(stdout, "   %-2d: 0x", pcr_id);

      // Print current PRC content (digest value)
      TPM2B_DIGEST *d = &pcrs->pcr_values[vi].digests[di];
      int k;
      for (k = 0; k < d->size; k++)
      {
        fprintf(stdout, "%02X", d->buffer[k]);
      }
      fprintf(stdout, "\n");

      if (++di >= pcrs->pcr_values[vi].count)
      {
        // if(vi+1 == pcr_select->count - 1 && di == 8)
        di = 0;
        ++vi;
      }
    }
  }

  return true;
}

TSS2_RC get_internal_attested_data(TPM2B_ATTEST *quoted, TPMS_ATTEST *attest)
{

  size_t offset = 0;
  TSS2_RC res = Tss2_MU_TPMS_ATTEST_Unmarshal(quoted->attestationData, quoted->size, &offset, attest);
  if (res != TSS2_RC_SUCCESS)
  {
    fprintf(stderr, "Cannot get digest from quote\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }
  return TSS2_RC_SUCCESS;
}

bool tpm2_openssl_hash_compute_data(TPMI_ALG_HASH halg, BYTE *buffer, UINT16 length, TPM2B_DIGEST *digest)
{

  if (halg != TPM2_ALG_SHA256)
  {
    fprintf(stderr, "Wrong HashAlgo\n");
    return false;
  }

  const EVP_MD *md = EVP_sha256(); // ctx.sig_hash_algorithm = TPM2_ALG_SHA256
  if (!md)
    return false;

  EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
  if (!mdctx)
    return false;

  int res = EVP_DigestInit_ex(mdctx, md, NULL);
  if (!res)
  {
    EVP_MD_CTX_destroy(mdctx);
    return false;
  }

  res = EVP_DigestUpdate(mdctx, buffer, length);
  if (!res)
  {
    EVP_MD_CTX_destroy(mdctx);
    return false;
  }

  unsigned size = EVP_MD_size(md);
  res = EVP_DigestFinal_ex(mdctx, digest->buffer, &size);
  if (!res)
  {
    EVP_MD_CTX_destroy(mdctx);
    return false;
  }

  digest->size = size;
  EVP_MD_CTX_destroy(mdctx);
  return true;
}

bool tpm2_public_load_pkey(const char *path, EVP_PKEY **pkey)
{
  BIO *bio = NULL;
  EVP_PKEY *p = NULL;

  bio = BIO_new_file(path, "rb");
  if (!bio)
    return false;

  p = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  if (!p)
  {
    fprintf(stderr, "Failed to convert public key from file '%s'\n", path);
    BIO_free(bio);
    return false;
  }
  *pkey = p;

  BIO_free(bio);
  return true;
}

bool tpm2_util_verify_digests(TPM2B_DIGEST *quoteDigest, TPM2B_DIGEST *pcr_digest)
{
  // Sanity check -- they should at least be same size!
  if (quoteDigest->size != pcr_digest->size)
  {
    fprintf(stderr, "FATAL ERROR: PCR values failed to match quote's digest!\n");
    return false;
  }
  // Compare running digest with quote's digest
  int k;
  for (k = 0; k < quoteDigest->size; k++)
  {
    if (quoteDigest->buffer[k] != pcr_digest->buffer[k])
    {
      fprintf(stderr, "FATAL ERROR: PCR values failed to match quote's digest!\n");
      return false;
    }
  }
  return true;
}

bool verify(void)
{
  bool res;
  EVP_PKEY_CTX *pkey_ctx = NULL;

  // Get the AK PubKey from file
  EVP_PKEY *pkey = NULL;
  tpm2_public_load_pkey(ctx.pubkey_file_path, &pkey);

  pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (!pkey_ctx)
  {
    fprintf(stderr, "EVP_PKEY_CTX_new failed\n");
    return false;
  }

  const EVP_MD *md = EVP_sha256(); // ctx.sig_hash_algorithm = TPM2_ALG_SHA256
  if (!md)
    return false;

  int rc = EVP_PKEY_verify_init(pkey_ctx);
  if (!rc)
  {
    fprintf(stderr, "EVP_PKEY_verify_init failed\n");
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    return false;
  }

  rc = EVP_PKEY_CTX_set_signature_md(pkey_ctx, md);
  if (!rc)
  {
    fprintf(stderr, "EVP_PKEY_CTX_set_signature_md failed\n");
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    return false;
  }

  rc = EVP_PKEY_verify(pkey_ctx, ctx.signature.buffer, ctx.signature.size, ctx.msg_hash.buffer, ctx.msg_hash.size);
  if (!rc)
  {
    fprintf(stderr, "Error validating signed message with public key provided\n");
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    return false;
  }

  // Ensure nonce is the same as given
  if (ctx.attest.extraData.size != ctx.extra_data.size || memcmp(ctx.attest.extraData.buffer, ctx.extra_data.buffer, ctx.extra_data.size) != 0)
  {
    fprintf(stderr, "Nonce from quote does not match nonce read from file\n");
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    return false;
  }

  // Make sure digest from quote matches calculated PCR digest
  rc = tpm2_util_verify_digests(&ctx.attest.attested.quote.pcrDigest, &ctx.pcr_hash);
  if (!rc)
  {
    fprintf(stderr, "Error: calculated PCRs digest does not match PCRs digest in the quote\n");
    return false;
  }

  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(pkey_ctx);
  return true;
}

bool tpm2_checkquote(TO_SEND TpaData)
{
  TSS2_RC tss_r = TSS2_RC_SUCCESS;
  bool res;
  int i;

  ctx.pubkey_file_path = "/etc/tc/ak.pub.pem";
  ctx.halg = TPM2_ALG_SHA256;
  // ctx.msg_file_path = "/etc/tc/quote.out";
  // ctx.sig_file_path = "/etc/tc/sig.out";
  // ctx.pcr_file_path = "/etc/tc/pcrs.out";
  //ctx.nonce_file_path = "/etc/tc/challenge";

  //ctx.extra_data.size = sizeof(ctx.extra_data.buffer);
  ctx.extra_data.size = TpaData.nonce_blob.size;
  memcpy(ctx.extra_data.buffer, TpaData.nonce_blob.buffer, ctx.extra_data.size);
  /*res = read_nonce_from_file(ctx.nonce_file_path, &ctx.extra_data.size, ctx.extra_data.buffer);
  if (!res)
    return false;*/

  TPM2B_ATTEST *msg = malloc(sizeof(TPM2B_ATTEST));
  msg->size = TpaData.message_blob.size;
  memcpy(msg->attestationData, TpaData.message_blob.buffer, msg->size);
  /*msg = message_from_file(ctx.msg_file_path);
  if(!msg) return false;*/

  ctx.signature.size = TpaData.sig_blob.size;
  memcpy(ctx.signature.buffer, TpaData.sig_blob.buffer, ctx.signature.size);
  /*res = tpm2_load_signature_from_path(ctx.sig_file_path, &ctx.signature);
  if (!res)
  {
    fprintf(stderr, "Error while loading signature\n");
    free(msg);
    return false;
  }*/

  TPML_PCR_SELECTION pcr_select;
  tpm2_pcrs *pcrs;
  //tpm2_pcrs temp_pcrs = {};

  // Read pcrs from the specified file
  /*if (!pcrs_from_file(ctx.pcr_file_path, &pcr_select, &temp_pcrs))
  {
    // Internal error log
    free(msg);
    return false;
  }*/
  // pcrs = &temp_pcrs;
  pcr_select = TpaData.pcrs_blob.pcr_selection;
  pcrs = &TpaData.pcrs_blob.pcrs;
  if (le32toh(pcr_select.count) > TPM2_NUM_PCR_BANKS)
  {
    free(msg);
    return false;
  }

  if (!tpm2_openssl_hash_pcr_banks(ctx.halg, &pcr_select, pcrs, &ctx.pcr_hash))
  {
    fprintf(stderr, "Failed to compute PCR hash of its values. Needed for comparing this with real calcDigest inside the quote\n");
    return false;
  }

  if (!pcr_print(&pcr_select, pcrs))
  {
    fprintf(stderr, "Failed to print PCRs \n");
    return false;
  }

  tss_r = get_internal_attested_data(msg, &ctx.attest);
  if (tss_r != TSS2_RC_SUCCESS)
  {
    fprintf(stderr, "Error while Unmarshalling TPM2B_ATTEST to TPMS_ATTEST needed to get all attested info\n");
    return false;
  }

  // Recompute the signature in order to compare it later with the one loaded in ctx.signature
  if (!tpm2_openssl_hash_compute_data(ctx.halg, msg->attestationData, msg->size, &ctx.msg_hash))
  {
    free(msg);
    fprintf(stderr, "Recomputation of quote signature failed!\n");
    return false;
  }
  free(msg);

  return verify();
}