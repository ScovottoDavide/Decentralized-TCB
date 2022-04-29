#include "PEMconvertPub.h"

EVP_PKEY *convert_pubkey_RSA(TPMT_PUBLIC *public) {

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    RSA *rsa_key = NULL;
#else
    OSSL_PARAM_BLD *build = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
#endif
    BIGNUM *e = NULL, *n = NULL;
    EVP_PKEY *pkey = NULL;

    UINT32 exponent = (public->parameters).rsaDetail.exponent;
    if (exponent == 0) {
        exponent = 0x10001;
    }

    n = BN_bin2bn(public->unique.rsa.buffer, public->unique.rsa.size, NULL);
    if (!n) {
        fprintf(stderr, "Failed to convert data to SSL internal format");
        goto error;
    }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    rsa_key = RSA_new();
    if (!rsa_key) {
        fprintf(stderr, "Failed to allocate OpenSSL RSA structure");
        goto error;
    }

    e = BN_new();
    if (!e) {
        fprintf(stderr, "Failed to convert data to SSL internal format");
        goto error;
    }
    int rc = BN_set_word(e, exponent);
    if (!rc) {
        fprintf(stderr, "Failed to convert data to SSL internal format");
        goto error;
    }

    rc = RSA_set0_key(rsa_key, n, e, NULL);
    if (!rc) {
        fprintf(stderr, "Failed to set RSA modulus and exponent components");
        goto error;
    }

    /* modulus and exponent components are now owned by the RSA struct */
    n = e = NULL;

    pkey = EVP_PKEY_new();
    if (!pkey) {
        fprintf(stderr, "Failed to allocate OpenSSL EVP structure");
        goto error;
    }

    rc = EVP_PKEY_assign_RSA(pkey, rsa_key);
    if (!rc) {
        fprintf(stderr, "Failed to set OpenSSL EVP structure");
        EVP_PKEY_free(pkey);
        pkey = NULL;
        goto error;
    }
    /* rsa key is now owner by the EVP_PKEY struct */
    rsa_key = NULL;
#else
    build = OSSL_PARAM_BLD_new();
    if (!build) {
        fprintf(stderr, "Failed to allocate OpenSSL parameters");
        goto error;
    }

    int rc = OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_N, n);
    if (!rc) {
        printf(stderr, "Failed to set RSA modulus");
        goto error;
    }

    rc = OSSL_PARAM_BLD_push_uint32(build, OSSL_PKEY_PARAM_RSA_E, exponent);
    if (!rc) {
        fprintf(stderr, "Failed to set RSA exponent");
        goto error;
    }

    params = OSSL_PARAM_BLD_to_param(build);
    if (!params) {
        fprintf(stderr, "Failed to build OpenSSL parameters");
        goto error;
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to allocate RSA key context");
        goto error;
    }

    rc = EVP_PKEY_fromdata_init(ctx);
    if (rc <= 0) {
        fprintf(stderr, "Failed to initialize RSA key creation");
        goto error;
    }

    rc = EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
    if (rc <= 0) {
        fprintf(stderr, "Failed to create a RSA public key");
        goto error;
    }
#endif
error:
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    RSA_free(rsa_key);
#else
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(build);
#endif
    BN_free(n);
    BN_free(e);
    return pkey;
}

static bool tpm2_convert_pubkey_bio(TPMT_PUBLIC *public, BIO *bio) {

  EVP_PKEY *pubkey = NULL;
  int ssl_res = 0;

  // Suupose public->type always TPM2_ALG_RSA
  if(public->type == TPM2_ALG_NULL)
    return false;
  pubkey = convert_pubkey_RSA(public);
  if(pubkey == NULL)
    return false;

  // Suppose format is always PEM
  ssl_res = PEM_write_bio_PUBKEY(bio, pubkey);

  EVP_PKEY_free(pubkey);
  if(ssl_res <= 0){
    fprintf(stderr, "OpenSSL public key conversion failed\n");
    return false;
  }

  return true;
}

static bool tpm2_convert_pubkey_ssl(TPMT_PUBLIC *public, const char *path) {
  BIO *bio = path ? BIO_new_file(path, "wb") : BIO_new_fp(stdout, BIO_NOCLOSE);
  if(!bio){
    fprintf(stderr, "Failed to open public key output file '%s'\n", path ? path : "<stdin>");
    return false;
  }

  bool res = tpm2_convert_pubkey_bio(public, bio);
  BIO_free(bio);
  return res;
}

bool tpm2_convert_pubkey_save(TPM2B_PUBLIC *public, const char *path) {
  return tpm2_convert_pubkey_ssl(&public->publicArea, path);
}
