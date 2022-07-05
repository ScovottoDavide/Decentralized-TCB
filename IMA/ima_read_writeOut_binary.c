#include "ima_read_writeOut_binary.h"

static int read_template_data(struct event *template, FILE *fp, struct event_blob *blob_template) {
	int len, is_ima_template, is_imang_template, i, acc = 0;

	is_ima_template = strcmp(template->name, "ima") == 0 ? 1 : 0;
	is_imang_template = strcmp(template->name, "ima-ng") == 0 ? 1: 0;

	if (!is_ima_template) {
		fread(&template->template_data_len, sizeof(u_int32_t), 1, fp);
		memcpy(&blob_template->template_data_len, &template->template_data_len, sizeof(u_int32_t));
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
		fprintf(stdout, "ERROR: out of memory\n");
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
	memcpy(blob_template->template_data + acc, &field_len, sizeof(u_int32_t));
	acc += sizeof(u_int32_t);
	if(field_len != 0x28) {
		fread(alg_sha1_field, sizeof(u_int8_t) , 6, fp);
		memcpy(blob_template->template_data + acc, alg_sha1_field, 6*sizeof(u_int8_t));
		acc += 6*sizeof(u_int8_t);

		fread(template->template_data, sizeof(u_int8_t), SHA_DIGEST_LENGTH, fp); /* [file hash] */
		memcpy(blob_template->template_data + acc, template->template_data, SHA_DIGEST_LENGTH*sizeof(u_int8_t));
		acc += SHA_DIGEST_LENGTH*sizeof(u_int8_t);
	} else {
		fread(alg_field, sizeof(u_int8_t) , 8, fp);
		memcpy(blob_template->template_data + acc, alg_field, 8*sizeof(u_int8_t));
		acc += 8*sizeof(u_int8_t);

		fread(template->template_data, sizeof(u_int8_t), SHA256_DIGEST_LENGTH, fp); /* [file hash] */
		memcpy(blob_template->template_data + acc, template->template_data, SHA256_DIGEST_LENGTH*sizeof(u_int8_t));
		acc += SHA256_DIGEST_LENGTH*sizeof(u_int8_t);
	}

	fread(&field_path_len, sizeof field_path_len, 1, fp); /* n-ng:[uint32 little endian path len] */
	memcpy(blob_template->template_data + acc, &field_path_len, sizeof field_path_len);
	acc += sizeof field_path_len;

	path_field = malloc(field_path_len*sizeof(u_int8_t));

	fread(path_field, sizeof(u_int8_t), field_path_len, fp); /* [file hash] */
	memcpy(blob_template->template_data + acc, path_field, field_path_len*sizeof(u_int8_t));
	acc += field_path_len*sizeof(u_int8_t);
	}
	return 0;
}

int read_write_IMAb(const char *path,  IMA_LOG_BLOB *ima_log_blob, ssize_t imaLogBytesSize){
	FILE *fp;
	struct event template;
	int local_size = 0, initial_log_size = 512, i;

	fp = fopen(path, "rb");
	if (!fp) {
		printf("fn: %s\n", path);
		perror("Unable to open file\n");
		return -1;
	}

	if(imaLogBytesSize == 0){
		/** Initialize the blob */
		ima_log_blob->tag = 4;
		ima_log_blob->size = 0;
		/** Preallocate some space for the logs */
		ima_log_blob->logEntry = malloc(initial_log_size*sizeof(struct event_blob));
	}else{
		fseek(fp, imaLogBytesSize, SEEK_SET);
	}

	while(fread(&template.header, sizeof template.header, 1, fp)){
		if(local_size >= initial_log_size){
			initial_log_size *= 2;
			ima_log_blob->logEntry = realloc(ima_log_blob->logEntry, initial_log_size*sizeof(struct event_blob));
		}
		if (template.header.name_len > TCG_EVENT_NAME_LEN_MAX) {
			printf("%d ERROR: event name too long!\n", template.header.name_len);
			fclose(fp);
			exit(-1);
		}
		memcpy(&ima_log_blob->logEntry[local_size].header.pcr, &template.header.pcr, sizeof(u_int32_t));
		memcpy(ima_log_blob->logEntry[local_size].header.digest, template.header.digest, SHA_DIGEST_LENGTH*sizeof(u_int8_t));
		memcpy(&ima_log_blob->logEntry[local_size].header.name_len, &template.header.name_len, sizeof(u_int32_t));

		memset(template.name, 0, sizeof template.name);
		fread(template.name, template.header.name_len, 1, fp);

		memcpy(ima_log_blob->logEntry[local_size].name, template.name, template.header.name_len*sizeof(char));

		if (read_template_data(&template, fp, &ima_log_blob->logEntry[local_size]) < 0) {
			printf("\nReading of measurement entry failed\n");
			exit(-1);
		}

		local_size++;
	}

	ima_log_blob->size = local_size;

	fclose(fp);
	return 0;
}
