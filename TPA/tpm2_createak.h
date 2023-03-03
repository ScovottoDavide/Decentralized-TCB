#if !defined(TPM2_CREATEAK_H)
#define TPM2_CREATEAK_H

#include "createak_util.h"
#include "PEMconvertPub.h"
#include "all_util.h"

typedef struct createak_context createak_context;
struct createak_context {
    struct {
        const char *ctx_arg;
        tpm2_loaded_object ek_ctx;
        tpm2_session *session;
        char *auth_str;
    } ek;
    struct {
        struct {
            TPM2B_SENSITIVE_CREATE in_sensitive;
            struct {
                const char *type;
                const char *digest;
                const char *sign;
            } alg;
        } in;
        struct {
            const char *ctx_file;
            // PEM
            //tpm2_convert_pubkey_fmt pub_fmt;
            const char *pub_file;
            const char *name_file;
            const char *priv_file;
            const char *qname_file;
        } out;
        char *auth_str;
        // Added by me for persisting the AK
        tpm2_loaded_object object;
    } ak;
    struct {
        UINT8 f :1;
    } flags;
};

static TSS2_RC init_ak_public(const char* alg_details, TPM2B_PUBLIC *public);
static TSS2_RC create_ak(ESYS_CONTEXT *ectx, uint16_t *ak_handle);
TSS2_RC tpm2_tool_onrun(ESYS_CONTEXT *ectx, uint16_t *ek_handle, uint16_t *ak_handle);
TSS2_RC tpm2_createak(ESYS_CONTEXT *ectx, uint16_t *ek_handle, uint16_t *ak_handle);
#endif