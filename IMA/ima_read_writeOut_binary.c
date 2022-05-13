#include "ima_read_writeOut_binary.h"

int swap_Endians(u_int32_t value) {
	int leftmost_byte;
	int left_middle_byle;
  int right_middle_byte;
  int rightmost_byte;
	int result;

  leftmost_byte = (value & 0x000000FF) >> 0;
	left_middle_byle = (value & 0x0000FF00) >> 8;
  right_middle_byte = (value & 0x00FF0000) >> 16;
  rightmost_byte = (value & 0xFF000000) >> 24;

  leftmost_byte <<= 24;

  left_middle_byle <<= 16;

  right_middle_byte <<= 8;

	rightmost_byte <<= 0;

  result = (leftmost_byte | left_middle_byle
              | right_middle_byte | rightmost_byte);

    return result;
}

static int display_digest(u_int8_t * digest, u_int32_t digestlen, FILE *fout) {
	int i;

	for (i = 0; i < digestlen; i++)
		fprintf(fout, "%02x", (*(digest + i) & 0xff));
	return 0;
}

static int read_template_data(struct event *template, FILE *fp, FILE *fout) {
	int len, is_ima_template, is_imang_template, i;

	is_ima_template = strcmp(template->name, "ima") == 0 ? 1 : 0;
	is_imang_template = strcmp(template->name, "ima-ng") == 0 ? 1: 0;

	if (!is_ima_template) {
		fread(&template->template_data_len, sizeof(u_int32_t), 1, fp);
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

	template->template_data = calloc(template->template_data_len, sizeof(u_int8_t));
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
		u_int32_t field_path_len;
		u_int8_t alg_field[8]; /* sha256:\0 */
		u_int8_t alg_sha1_field[6]; /* sha1:\0 */
		u_int8_t *path_field;

		fread(&field_len, sizeof(u_int32_t), 1, fp); /* d-ng:[uint32 little endian hash len]* */
      	fwrite(&field_len, sizeof(u_int32_t), 1, fout);
		if(field_len != 0x28) {
			fread(alg_sha1_field, sizeof(u_int8_t) , 6, fp);
      		fwrite(alg_sha1_field, sizeof(u_int8_t) , 6, fout);
	
			fread(template->template_data, sizeof(u_int8_t), SHA_DIGEST_LENGTH, fp); /* [file hash] */
			fwrite(template->template_data, sizeof(u_int8_t), SHA_DIGEST_LENGTH, fout);
		} else {
			fread(alg_field, sizeof(u_int8_t) , 8, fp);
      		fwrite(alg_field, sizeof(u_int8_t) , 8, fout);
			
			fread(template->template_data, sizeof(u_int8_t), SHA256_DIGEST_LENGTH, fp); /* [file hash] */
			fwrite(template->template_data, sizeof(u_int8_t), SHA256_DIGEST_LENGTH, fout);
		}

		
		fread(&field_path_len, sizeof field_path_len, 1, fp); /* n-ng:[uint32 little endian path len] */
      	fwrite(&field_path_len, sizeof field_path_len, 1, fout);
	
		path_field = malloc(field_path_len*sizeof(u_int8_t));

		fread(path_field, sizeof(u_int8_t), field_path_len, fp); /* [file hash] */
		fwrite(path_field, sizeof(u_int8_t), field_path_len, fout);
		
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
  	fout = fopen("/etc/tc/IMA_LOG_OUT", "w");
  	if(!fout){
    	perror("Unable to create file\n");
    	return -1;
  	}

  	while(fread(&template.header, sizeof template.header, 1, fp)){
    	//fprintf(stdout, "%03x %03x ", template.header.pcr, template.header.name_len);
    	//display_digest(template.header.digest, SHA_DIGEST_LENGTH, fout);
    	if (template.header.name_len > TCG_EVENT_NAME_LEN_MAX) {
			printf("%d ERROR: event name too long!\n", template.header.name_len);
			fclose(fp);
      		fclose(fout);
			exit(-1);
		}
    	fwrite(&template.header.pcr, sizeof(u_int32_t), 1, fout);
		fwrite(&template.header.digest, SHA_DIGEST_LENGTH*sizeof(u_int8_t), 1, fout);
		fwrite(&template.header.name_len, sizeof(u_int32_t), 1, fout);
    	memset(template.name, 0, sizeof template.name);
    	fread(template.name, template.header.name_len, 1, fp);
    	fwrite(&template.name, template.header.name_len*sizeof(char), 1, fout);

		if (read_template_data(&template, fp, fout) < 0) {
			printf("\nReading of measurement entry failed\n");
			exit(-1);
		}
	}

  	fclose(fp);
  	fclose(fout);
  	return 0;
  }