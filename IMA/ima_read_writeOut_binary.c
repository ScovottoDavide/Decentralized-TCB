#include "ima_read_writeOut_binary.h"

static int display_digest(u_int8_t * digest, u_int32_t digestlen, FILE *fout) {
	int i;

	for (i = 0; i < digestlen; i++)
		fprintf(fout, "%02x", (*(digest + i) & 0xff));
	return 0;
}

static int read_template_data(struct event *template, FILE *fp, FILE *fout) {
	int len, is_ima_template, is_imang_template;

	is_ima_template = strcmp(template->name, "ima") == 0 ? 1 : 0;
	is_imang_template = strcmp(template->name, "ima-ng") == 0 ? 1: 0;

	if (!is_ima_template) {
		fread(&template->template_data_len, sizeof(u_int32_t), 1, fp);
		//fprintf(fout, " 0x%02x ", template->template_data_len);
    fwrite(&template->template_data_len, sizeof(u_int32_t), 1, fout);
		len = template->template_data_len;
	} else {
		template->template_data_len = SHA_DIGEST_LENGTH +
		    TCG_EVENT_NAME_LEN_MAX + 1;
		/*
		 * Read the digest only as the event name length
		 * is not known in advance.
		 */
		len = SHA_DIGEST_LENGTH;
	}

	template->template_data = calloc(template->template_data_len,
					 sizeof(u_int8_t));
	if (template->template_data == NULL) {
		printf("ERROR: out of memory\n");
		return -ENOMEM;
	}

	if (is_ima_template) {	/* finish 'ima' template data read */
		u_int32_t field_len;
		fread(template->template_data, len, 1, fp);

		fread(&field_len, sizeof(u_int32_t), 1, fp);
		fread(template->template_data + SHA_DIGEST_LENGTH,field_len, 1, fp);
	}else if (is_imang_template){ /* finish 'ima-ng' template data read */
			u_int32_t field_len;
			u_int8_t alg_field[8]; /* sha256:\0 */
			u_int8_t *path_field;

			fread(&field_len, sizeof(u_int32_t), 1, fp); /* d-ng:[uint32 little endian hash len]* */
			//fprintf(fout, " 0x%02x ", field_len);
      fwrite(&field_len, sizeof(u_int32_t), 1, fout);
			fread(alg_field, sizeof(alg_field), 1, fp);
      fwrite(alg_field, sizeof(alg_field), 1, fout);
			int i;
			/*for(i=0; i<8; i++)
				fprintf(fout, "%c", alg_field[i]);*/
			fread(template->template_data, SHA256_DIGEST_LENGTH, 1, fp); /* [file hash] */
      fwrite(template->template_data, SHA256_DIGEST_LENGTH, 1, fout);
			/*for(i=0; i<SHA256_DIGEST_LENGTH; i++)
				fprintf(fout, " %02x", template->template_data[i]);*/
			fread(&field_len, sizeof(u_int32_t), 1, fp); /* n-ng:[uint32 little endian path len] */
      fwrite(&field_len, sizeof(u_int32_t), 1, fout);
			//fprintf(fout, " %02x ", field_len);
			path_field = malloc(field_len*sizeof(u_int8_t));
			fread(path_field, field_len, 1, fp); /* [file hash] */
      fwrite(path_field, field_len, 1, fout);
			/*for(i=0; i<field_len; i++)
				fprintf(fout, "%c", path_field[i]);
			fprintf(fout, "\n");*/
	}
	return 0;
}

int read_write_IMAb(const char *path){
  FILE *fp;
  struct event template;

  fp = fopen(path, "rb");
	if (!fp) {
		printf("fn: %s\n", path);
		perror("Unable to open file\n");
		return -1;
	}

  FILE *fout;
  fout = fopen("../IMA/IMA_LOG_OUT", "w");
  if(!fout){
    perror("Unable to create file\n");
    return -1;
  }

  while(fread(&template.header, sizeof template.header, 1, fp)){
    //fprintf(fout, "%03x %03x ", template.header.pcr, template.header.name_len);
    //display_digest(template.header.digest, SHA_DIGEST_LENGTH, fout);
    if (template.header.name_len > TCG_EVENT_NAME_LEN_MAX) {
			printf("%d ERROR: event name too long!\n",
				template.header.name_len);
			fclose(fp);
      fclose(fout);
			exit(1);
		}
    fwrite(&template.header, sizeof template.header, 1, fout);
    memset(template.name, 0, sizeof template.name);
    fread(template.name, template.header.name_len, 1, fp);
    fwrite(&template.name, template.header.name_len, 1, fout);
    //fprintf(fout, " %s", template.name);

		if (read_template_data(&template, fp, fout) < 0) {
			printf("\nReading of measurement entry failed\n");
			exit(-1);
		}
	}

  const char eof = EOF;
  fwrite(&eof, sizeof(char), 1, fout);

  fclose(fp);
  fclose(fout);
  return 0;
}

/*int main(){
  read_write_IMAb("/sys/kernel/security/integrity/ima/binary_runtime_measurements");
  return 0;
}*/
