#include "tpm2_checkquote.h"

typedef struct tpm2_verifysig_ctx tpm2_verifysig_ctx;
struct tpm2_verifysig_ctx {
    TPMI_ALG_HASH halg;
    TPM2B_DIGEST msg_hash;
    TPM2B_DIGEST pcr_hash;
    TPMS_ATTEST attest;
    TPM2B_DATA extra_data;
    TPM2B_MAX_BUFFER signature;
    char *msg_file_path;
    char *sig_file_path;
    char *out_file_path;
    char *pcr_file_path;
    char *nonce_file_path;
    const char *pubkey_file_path;
    tpm2_loaded_object key_context_object;
    const char *pcr_selection_string;
};


static tpm2_verifysig_ctx ctx = {
        .halg = TPM2_ALG_NULL,
        .msg_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer),
        .pcr_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer),
};

bool files_get_file_size(FILE *fp, unsigned long *file_size, const char *path) {

    long current = ftell(fp);
    if (current < 0) {
        if (path) {
            fprintf(stderr, "Error getting current file offset for file \"%s\"", path);
        }
        return false;
    }

    int rc = fseek(fp, 0, SEEK_END);
    if (rc < 0) {
        if (path) {
            fprintf(stderr, "Error seeking to end of file \"%s\"", path);
        }
        return false;
    }

    long size = ftell(fp);
    if (size < 0) {
        if (path) {
            fprintf(stderr, "ftell on file \"%s\" failed", path);
        }
        return false;
    }

    rc = fseek(fp, current, SEEK_SET);
    if (rc < 0) {
        if (path) {
           fprintf(stderr, "Cannot restore initial seek position on file \"%s\"", path);
        }
        return false;
    }

    /* size cannot be negative at this point */
    *file_size = (unsigned long) size;
    return true;
}

bool read_nonce_from_file(const char *input, UINT16 *len, BYTE *buffer) {
    FILE *f = fopen(input, "rb");
    if(!f){
        fprintf(stderr, "Could not open %s file\n", input);
        return false;
    }

    unsigned long file_size;
    bool res = files_get_file_size(f, &file_size, input);
    if(!res) return false;

    //fprintf(stdout, "filesize: %d\n", file_size);
    if(file_size > *len){
        fprintf(stderr, "File size is greater than buffer capability\n");
        return false;
    }

    *len = file_size;
    size_t count = 0;
    do{
        count += fread(&buffer[count], 1, *len-count, f);
    } while( count < *len && !feof(f));
   
    if(*len < file_size){
        fprintf(stderr, "Could not read any data from file!\n");
        return false;
    }
    //fprintf(stdout, "1: %s %d\n", buffer, strlen(buffer));
    fclose(f);
    return true;
}

TPM2B *message_from_file(const char *msg_file_path) {
    unsigned long size;

    FILE *f = fopen(msg_file_path, "rb");
    if(!f){
        fprintf(stderr, "Could not open %s file\n", msg_file_path);
        return false;
    }
    bool res = files_get_file_size(f, &size, msg_file_path);
    if(!res || !size){
        fprintf(stderr, "Could not get \"%s\" size\n", msg_file_path);
        fclose(f);
        return NULL;
    }
    fclose(f);

    TPM2B *msg = (TPM2B *) calloc(1, sizeof(TPM2B) + size);
    if(!msg){
        fprintf(stderr, "OOM\n");
        return NULL;
    }

    UINT16 tpm = msg->size = size;
    if(!read_nonce_from_file(msg_file_path, &tpm, msg->buffer)){
        free(msg);
        return NULL;
    }
    return msg;
}

bool tpm2_load_signature_from_path(const char *path, TPM2B_MAX_BUFFER *signature) {
    signature->size = sizeof(signature->buffer);

    // this case is not the nonce but the signature
    return read_nonce_from_file(path, &signature->size, signature->buffer);
}

TSS2_RC tpm2_checkquote() {
    TSS2_RC tss_r = TSS2_RC_SUCCESS;
    bool res;

    ctx.pubkey_file_path = "/etc/tc/ak.pub.pem";
    ctx.halg = TPM2_ALG_SHA256;
    ctx.msg_file_path = "/etc/tc/quote.out";
    ctx.sig_file_path = "/etc/tc/sig.out";
    ctx.pcr_file_path = "/etc/tc/pcrs.out";
    ctx.nonce_file_path = "/etc/tc/challenge";

    if (!(ctx.pubkey_file_path && ctx.msg_file_path && ctx.sig_file_path && ctx.pcr_file_path && ctx.nonce_file_path)) {
        fprintf(stderr, "Missing resources needed to validate the quote\n");
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    ctx.extra_data.size = sizeof(ctx.extra_data.buffer);
    res = read_nonce_from_file(ctx.nonce_file_path, &ctx.extra_data.size, ctx.extra_data.buffer);
    if(!res)
        return TSS2_ESYS_RC_BAD_VALUE;
    
    TPM2B_ATTEST *msg = NULL;
    msg = (TPM2B_ATTEST*) message_from_file(ctx.msg_file_path);
    if(!msg) return TSS2_ESYS_RC_BAD_VALUE;

    res = tpm2_load_signature_from_path(ctx.sig_file_path, &ctx.signature);
    if(!res){
        fprintf(stderr, "Error while loading signature\n");
        free(msg);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return tss_r;
}