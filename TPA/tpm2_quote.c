#include "tpm2_quote.h"
#include "createak_util.h"

typedef struct tpm_quote_ctx tpm_quote_ctx;
struct tpm_quote_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } key;

    //tpm2_convert_sig_fmt sig_format;
    TPMI_ALG_HASH sig_hash_algorithm;
    TPM2B_DATA qualification_data;
    TPML_PCR_SELECTION pcr_selections;
    TPMS_CAPABILITY_DATA cap_data;
    //tpm2_pcrs pcrs;
    //tpm2_convert_pcrs_output_fmt pcrs_format;
    TPMT_SIG_SCHEME in_scheme;
    TPMI_ALG_SIG_SCHEME sig_scheme;

    /*
     * Outputs
     */
    FILE *pcr_output;
    char *pcr_path;
    char *signature_path;
    char *message_path;
    TPMS_ATTEST attest;
    TPM2B_ATTEST *quoted;
    TPMT_SIGNATURE *signature;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

static tpm_quote_ctx ctx = {
    .sig_hash_algorithm = TPM2_ALG_NULL,
    //.qualification_data = TPM2B_EMPTY_INIT,
    //.pcrs_format = pcrs_output_format_serialized,
    .in_scheme.scheme = TPM2_ALG_NULL,
    .sig_scheme = TPM2_ALG_NULL,
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

/*    TPMS_PCR_SELECTION = TPMS_PCR_SELECT + HASH (hash algo associated with the selection)
*     FROM THE TCG PAPERS
* This structure provides a standard method of specifying a list of PCR. 
* PCR numbering starts at zero.
* pcrSelect is an array of octets. The octet containing the bit corresponding to a specific PCR is found by 
* dividing the PCR number by 8.
* EXAMPLE 1 --> The bit in pcrSelect corresponding to PCR 19 is in pcrSelect [2] (19/8 = 2)
* The least significant bit in a octet is bit number 0. The bit in the octet associated with a PCR is the
* remainder after division by 8.
* EXAMPLE 2 --> The bit in pcrSelect [2] corresponding to PCR 19 is bit 3 (19 mod 8). If sizeofSelect is 3, then the
*               pcrSelect array that would specify PCR 19 and no other PCR is 00 00 08(hex 16).
* Each bit in pcrSelect indicates whether the corresponding PCR is selected (1) or not (0). If the pcrSelect
* is all zero bits, then no PCR is selected.
*/

bool pcr_parse_list(const char *str, size_t len, TPMS_PCR_SELECTION *pcr_select) {
    char buf[4];
    const char *current_string;
    int current_length;
    UINT32 pcr;
    bool res;

    if(str == NULL || len == 0 || strlen(str) == 0)
        return false;
    
    pcr_select->sizeofSelect = 3;
    pcr_select->pcrSelect[0] = 0;
    pcr_select->pcrSelect[1] = 0;
    pcr_select->pcrSelect[2] = 0;

    if (!strncmp(str, "all", 3)) {
       pcr_select->pcrSelect[0] = 0xff;
       pcr_select->pcrSelect[1] = 0xff;
       pcr_select->pcrSelect[2] = 0xff;
       return true;
    }
    
    if (!strncmp(str, "none", 4)) {
       pcr_select->pcrSelect[0] = 0x00;
       pcr_select->pcrSelect[1] = 0x00;
       pcr_select->pcrSelect[2] = 0x00;
       return true;
    }

    do{
        current_string = str;
        str = memchr(current_string, ',', len);
        if(str){
            current_length = str - current_string;
            str++;
            len -= current_length + 1;
        } else {
            current_length = len;
            len = 0;
        }

        if((size_t) current_length > sizeof(buf) - 1)
            return false;
        
        snprintf(buf, current_length + 1, "%s", current_string);

        // get pcr from string 
        res = tpm2_util_handle_from_optarg(buf, &pcr, TPM2_HANDLE_FLAGS_PCR);
        
        pcr_select->pcrSelect[pcr / 8] |= (1 << (pcr%8));
    }while(str);

    return true;
}

bool pcr_parse_selections(const char *arg, TPML_PCR_SELECTION *pcr_select) {
    const char *left_string = arg;
    const char *current_string = arg;
    int current_length = 0;

    if(arg == NULL || pcr_select == NULL)
        return false;
    
    pcr_select->count = 0;

    do {
        // they both point at arg[0]
        current_string = left_string;

        // find 1st occurence of + and return the pointer of it if present else NULL
        left_string = strchr(current_string, '+'); 
        if(left_string){
            // left_string points at +, current_string points at arg[0]
            // calculate the length from the start of the string til the +
            current_length = left_string - current_string;
            // make left_string point after the '+' (the next "bank")
            left_string++;
        } else
            //if no '+' then consider the whole string
            current_length = strlen(current_string);
        
        const char *internal_string = NULL; // support string for parsing after splitting the '+'
        char buf[9] = { 0 }; // to detect if the halgName is too long (max is 8)

        internal_string = memchr(current_string, ':', current_length);

        if(internal_string == NULL)
            return false;
        if((size_t) (internal_string - current_string) > sizeof(buf) - 1)
            return false;
        
        // get from the current string the hash alg name and save it in buf
        snprintf(buf, internal_string - current_string + 1, "%s", current_string);
        buf[strlen(buf)] = '\0';

        if(strncmp(buf, "sha1", 4) == 0){
            pcr_select->pcrSelections[pcr_select->count].hash = TPM2_ALG_SHA1;
        } else if(strncmp(buf, "sha256", 6) == 0){
            pcr_select->pcrSelections[pcr_select->count].hash = TPM2_ALG_SHA256;
        } else if(strncmp(buf, "sha384", 6) == 0){
            pcr_select->pcrSelections[pcr_select->count].hash = TPM2_ALG_SHA384;
        } else if(strncmp(buf, "sha512", 6) == 0){
            pcr_select->pcrSelections[pcr_select->count].hash = TPM2_ALG_SHA512;
        } else {
            printf("Hash algorithm specified not valid. Got %s\n", buf);
            return false;
        }

        // once got the algo, move towards the list of pcrs
        internal_string++; 
        if((size_t) (internal_string - current_string) >= current_length)
            return false;

        if (!pcr_parse_list(internal_string, current_string + current_length - internal_string, &pcr_select->pcrSelections[pcr_select->count]))
            return false;

        pcr_select->count++;
    }while(left_string);

    if (pcr_select->count == 0)
        return false;

    return true;
}

bool read_nonce_from_file(const char *input, UINT16 *len, BYTE *buffer){
    int read = 0;
    FILE *f = fopen(input, "rb");
    if(!f){
        fprintf(stderr, "Could not open %s file\n", input);
        return false;
    }

    read = fread(buffer, *len, 1, f);
    
    if(read <= 0 || read > 1){
        fprintf(stderr, "Could not read any data from file!\n");
        return false;
    }

    fclose(f);
    return true;
}

TSS2_RC pcr_get_banks(ESYS_CONTEXT *esys_context, TPMS_CAPABILITY_DATA *capability_data, tpm2_algorithm *algs) { 
    TPMI_YES_NO more_data;
    TPMS_CAPABILITY_DATA *capdata_ret;

    TSS2_RC rc = tpm2_get_capability(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, TPM2_CAP_PCRS, TPM2_HR_PCR , TPM2_PCR_SELECT_MAX,
            &more_data, &capdata_ret);
    if (rc != TSS2_RC_SUCCESS) {
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    *capability_data = *capdata_ret;
    // If the TPM support more bank algorithm that we currently
    // able to manage, throw an error
    if (capability_data->data.assignedPCR.count > sizeof(algs->alg)) {
        fprintf(stderr, "Current implementation does not support more than %zu banks, ", sizeof(algs->alg));
        free(capdata_ret);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    unsigned i;
    for (i = 0; i < capability_data->data.assignedPCR.count; i++) {
        algs->alg[i] = capability_data->data.assignedPCR.pcrSelections[i].hash;
    }
    algs->count = capability_data->data.assignedPCR.count;
    free(capdata_ret);

    return TSS2_RC_SUCCESS;
}

TSS2_RC tpm2_quote(ESYS_CONTEXT *esys_ctx) {
    bool res;
    TSS2_RC tss_r;

    // AK handle --> supposed to be fixed on this value
    ctx.key.ctx_path = "0x81000001";
    ctx.key.auth_str = NULL;

    // parse ocr list --> sha1:0,1,2,3,4,5,6,7,8,9,10+sha256:0,1,2,3,4,5,6,7,8,9,10
    res = pcr_parse_selections("sha1:0,1,2,3,4,5,6,7,8,9,10+sha256:0,1,2,3,4,5,6,7,8,9,10", &ctx.pcr_selections);
    if(!res)
        return TSS2_ESYS_RC_BAD_VALUE;

    ctx.qualification_data.size = sizeof(ctx.qualification_data.buffer);
    res = read_nonce_from_file("/etc/tc/nonce_challange", &ctx.qualification_data.size, ctx.qualification_data.buffer);
    if(!res) 
        return TSS2_ESYS_RC_BAD_VALUE;

    ctx.message_path = "/etc/tc/quote.out";
    ctx.signature_path = "/etc/tc/sig.out";
    ctx.pcr_path = "/etc/tc/pcrs.out";
    ctx.sig_hash_algorithm = TPM2_ALG_SHA256;

    tss_r = tpm2_util_object_load_auth(esys_ctx, ctx.key.ctx_path, ctx.key.auth_str, &ctx.key.object, false, TPM2_HANDLE_ALL_W_NV);
    if(tss_r != TSS2_RC_SUCCESS) {
        printf("Error while authorizing for AK!\n");
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    ctx.pcr_output = fopen(ctx.pcr_path, "wb+");
    if (!ctx.pcr_output) {
        fprintf(stderr, "Could not open PCR output file \"%s\" \n",ctx.pcr_path);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    tpm2_algorithm algs;
    tss_r = pcr_get_banks(esys_ctx, &ctx.cap_data, &algs);
    if(tss_r != TSS2_RC_SUCCESS){
        printf("Error while getting pcr banks!\n");
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}