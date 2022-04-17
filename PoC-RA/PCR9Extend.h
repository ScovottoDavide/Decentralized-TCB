#include <tss2/tss2_esys.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

bool openAKPub(const char *path, unsigned char **akPub);
bool computeDigest(unsigned char* akPub, const char* sha_alg, unsigned char **digest);
TSS2_RC ExtendPCR9(ESYS_CONTEXT *ectx);
