#include "whitelist_verify.h"

bool loadWhitelist(FILE *fp, struct whitelist_entry *white_entries, int size){
    unsigned char digest[64];
    unsigned char path[256];
    int i = 0;
    for(i=0; i<size; i++){
        fscanf(fp, "%s %s", digest, path);
        //strncpy(white_entries[i].digest, digest, DIGEST_LEN);
        //strncpy(white_entries[i].path, path, strlen(path));
        fprintf(stdout, "%s %s\n", digest, path);
    }
    return true;
}

int verify() {
    struct event template;
    struct whitelist_entry *white_entries;
    FILE *ima_fp, *whitelist_fp;
    int num_entries = 0;

    ima_fp = fopen("/etc/tc/IMA_LOG_OUT", "rb");
    if(!ima_fp){
        fprintf(stdout, "Could not open IMA_LOG\n");
        exit(-1);
    }

    whitelist_fp = fopen("whitelist", "rb");
    if(!whitelist_fp){
        fprintf(stdout, "Could not open whitelist file\n");
        exit(-1);
    }

    fscanf(whitelist_fp, "%d", &num_entries);
    white_entries = malloc(num_entries * sizeof(struct whitelist_entry));
    if(!white_entries){
        fprintf(stdout, "OOM %d\n", num_entries);
        exit(-1);
    }

    loadWhitelist(whitelist_fp, white_entries, num_entries);
    /*while(fread(&template.header, sizeof template.header, 1, fp)){
    	if (template.header.name_len > TCG_EVENT_NAME_LEN_MAX) {
			printf("%d ERROR: event name too long!\n", template.header.name_len);
			fclose(fp);
      		fclose(fout);
			exit(-1);
		}
    	memset(template.name, 0, sizeof template.name);
    	fread(template.name, template.header.name_len, 1, fp);

		if (read_template_data(&template, fp, fout) < 0) {
			printf("\nReading of measurement entry failed\n");
			exit(-1);
		}
	}*/

    fclose(ima_fp);
    fclose(whitelist_fp);

    return 0;
}

int main(){
    verify();

    return 0;
}