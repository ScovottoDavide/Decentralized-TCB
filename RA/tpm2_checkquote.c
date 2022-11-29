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
  u_int8_t *pubkey_file_path;
};

static tpm2_verifysig_ctx ctx = {
    .halg = TPM2_ALG_SHA256,
    .msg_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer),
    .pcr_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer),
};

u_int8_t* get_ak_file_path(AK_FILE_TABLE *ak_table, TO_SEND TpaData, int nodes_number) {
  int i;
  for(i = 0; i < nodes_number; i++) {
    if(!memcmp(ak_table[i].ak_md, TpaData.ak_digest_blob.buffer, TpaData.ak_digest_blob.size))
      return ak_table[i].path_name;
  }
  return NULL;
}

bool calculate_pcr_digest(unsigned char *pcr10_sha256, unsigned char *pcr10_sha1, unsigned char *pcr9_sha256, unsigned char *pcr9_sha1,
                            TPMI_ALG_HASH hash_alg, TPM2B_DIGEST *digest){
  
  if (hash_alg != TPM2_ALG_SHA256) {
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
  if (!res) {
    EVP_MD_CTX_destroy(mdctx);
    return false;
  }

  res = EVP_DigestUpdate(mdctx, pcr9_sha1, SHA_DIGEST_LENGTH);
  res = EVP_DigestUpdate(mdctx, pcr10_sha1, SHA_DIGEST_LENGTH);
  res = EVP_DigestUpdate(mdctx, pcr9_sha256, SHA256_DIGEST_LENGTH);
  res = EVP_DigestUpdate(mdctx, pcr10_sha256, SHA256_DIGEST_LENGTH);

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

TSS2_RC get_internal_attested_data(TPM2B_ATTEST *quoted, TPMS_ATTEST *attest) {
  size_t offset = 0;
  TSS2_RC res = Tss2_MU_TPMS_ATTEST_Unmarshal(quoted->attestationData, quoted->size, &offset, attest);
  if (res != TSS2_RC_SUCCESS) {
    fprintf(stderr, "Cannot get digest from quote\n");
    return TSS2_ESYS_RC_BAD_VALUE;
  }
  return TSS2_RC_SUCCESS;
}

bool tpm2_openssl_hash_compute_data(TPMI_ALG_HASH halg, BYTE *buffer, UINT16 length, TPM2B_DIGEST *digest) {
  if (halg != TPM2_ALG_SHA256) {
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
  if (!res) {
    EVP_MD_CTX_destroy(mdctx);
    return false;
  }

  res = EVP_DigestUpdate(mdctx, buffer, length);
  if (!res) {
    EVP_MD_CTX_destroy(mdctx);
    return false;
  }

  unsigned size = EVP_MD_size(md);
  res = EVP_DigestFinal_ex(mdctx, digest->buffer, &size);
  if (!res) {
    EVP_MD_CTX_destroy(mdctx);
    return false;
  }

  digest->size = size;
  EVP_MD_CTX_destroy(mdctx);
  return true;
}

bool tpm2_public_load_pkey(const char *path, EVP_PKEY **pkey) {
  BIO *bio = NULL;
  EVP_PKEY *p = NULL;

  bio = BIO_new_file(path, "rb");
  if (!bio)
    return false;
  p = PEM_read_bio_PUBKEY(bio, &p, NULL, NULL);
  if (!p) {
    fprintf(stderr, "Failed to convert public key from file '%s'\n", path);
    //BIO_free(bio);
    return false;
  }
  *pkey = p;
  //BIO_free(bio);
  return true;
}

bool tpm2_util_verify_digests(TPM2B_DIGEST *quoteDigest, TPM2B_DIGEST *pcr_digest) {
  // Sanity check -- they should at least be same size!
  if (quoteDigest->size != pcr_digest->size) {
    fprintf(stderr, "FATAL ERROR: PCR values failed to match quote's digest!\n");
    return false;
  }
  // Compare running digest with quote's digest
  int k;
  for (k = 0; k < quoteDigest->size; k++) {
    if (quoteDigest->buffer[k] != pcr_digest->buffer[k]) {
      fprintf(stderr, "FATAL ERROR: PCR values failed to match quote's digest!\n");
      return false;
    }
  }
  return true;
}

bool verify(void) {
  bool res;
  EVP_PKEY_CTX *pkey_ctx = NULL;

  // Get the AK PubKey from file
  EVP_PKEY *pkey = NULL;

  tpm2_public_load_pkey(ctx.pubkey_file_path, &pkey);

  pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (!pkey_ctx) {
    fprintf(stderr, "EVP_PKEY_CTX_new failed\n");
    goto end;
  }

  const EVP_MD *md = EVP_sha256(); // ctx.sig_hash_algorithm = TPM2_ALG_SHA256
  if (!md)
    goto end;

  int rc = EVP_PKEY_verify_init(pkey_ctx);
  if (!rc) {
    fprintf(stderr, "EVP_PKEY_verify_init failed\n");
    goto end;
  }

  rc = EVP_PKEY_CTX_set_signature_md(pkey_ctx, md);
  if (!rc) {
    fprintf(stderr, "EVP_PKEY_CTX_set_signature_md failed\n");
    goto end;
  }

  rc = EVP_PKEY_verify(pkey_ctx, ctx.signature.buffer, ctx.signature.size, ctx.msg_hash.buffer, ctx.msg_hash.size);
  if (rc != 1) {
    fprintf(stderr, "Error validating signed message with public key provided: rc = %d\n", rc);
    goto end;
  }

  // Ensure nonce is the same as given
  if (ctx.attest.extraData.size != ctx.extra_data.size || memcmp(ctx.attest.extraData.buffer, ctx.extra_data.buffer, ctx.extra_data.size) != 0) {
    fprintf(stderr, "Nonce from quote does not match nonce read from file\n");
    goto end;
  }

  // Make sure digest from quote matches calculated PCR digest
  rc = tpm2_util_verify_digests(&ctx.attest.attested.quote.pcrDigest, &ctx.pcr_hash);
  if (!rc) {
    fprintf(stderr, "Error: calculated PCRs digest does not match PCRs digest in the quote\n");
    goto end;
  }

  return true;

end:
  //EVP_PKEY_free(pkey);
  //EVP_PKEY_CTX_free(pkey_ctx);
  return false;
}

bool tpm2_checkquote(TO_SEND TpaData, NONCE_BLOB nonce_blob, AK_FILE_TABLE *ak_table, int nodes_number, unsigned char *pcr10_sha256, unsigned char *pcr10_sha1,
                    unsigned char *pcr9_sha256, unsigned char *pcr9_sha1) {
  TSS2_RC tss_r = TSS2_RC_SUCCESS;
  bool res;
  int i;
  
  ctx.pubkey_file_path = get_ak_file_path(ak_table, TpaData, nodes_number);
  ctx.halg = TPM2_ALG_SHA256;

  ctx.extra_data.size = nonce_blob.size;
  memcpy(ctx.extra_data.buffer, nonce_blob.buffer, ctx.extra_data.size);

  TPM2B_ATTEST *msg = malloc(sizeof(TPM2B_ATTEST));
  if(msg == NULL){
    fprintf(stdout, "OOM \n");
    return false;
  }

  msg->size = TpaData.message_blob.size;
  memcpy(msg->attestationData, TpaData.message_blob.buffer, msg->size);

  ctx.signature.size = TpaData.sig_blob.size;
  memcpy(ctx.signature.buffer, TpaData.sig_blob.buffer, ctx.signature.size);

  if (!calculate_pcr_digest(pcr10_sha256, pcr10_sha1, pcr9_sha256, pcr9_sha1, ctx.halg, &ctx.pcr_hash)){
    fprintf(stderr, "Failed to compute PCR hash of its values. Needed for comparing this with real calcDigest inside the quote\n");
    return false;
  }
  
  tss_r = get_internal_attested_data(msg, &ctx.attest);
  if (tss_r != TSS2_RC_SUCCESS) {
    fprintf(stderr, "Error while Unmarshalling TPM2B_ATTEST to TPMS_ATTEST needed to get all attested info\n");
    return false;
  }

  // Recompute the signature in order to compare it later with the one loaded in ctx.signature
  if (!tpm2_openssl_hash_compute_data(ctx.halg, msg->attestationData, msg->size, &ctx.msg_hash)) {
    fprintf(stderr, "Recomputation of quote signature failed!\n");
    return false;
  }
  //free(msg);
  return verify();
}