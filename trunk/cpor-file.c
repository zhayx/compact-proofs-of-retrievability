

/* cpor_tag_file:
*/
int cpor_tag_file(char *filepath, size_t filepath_len){

	unsigned char *k_prf = NULL;
	unsigned char *t0 = NULL;
	
	size_t t0_size = 0;

	/* Allocate memory */
	if( ((tag->k_prf = malloc(CPOR_PRF_KEY_SIZE)) == NULL)) goto cleanup;
	memset(tag->k_prf, 0, CPOR_PRF_KEY_SIZE);
	if( ((t0 = malloc(CPOR_AES_KEY_SIZE)) == NULL)) goto cleanup;
	memset(t0, 0, CPOR_AES_KEY_SIZE);
	t0_size = CPOR_AES_KEY_SIZE;

	file = fopen(filepath, "r");
	if(!file){
		fprintf(stderr, "ERROR: Was not able to open %s for reading.\n", filepath);
		goto cleanup;
	}

	/*  generate a random PRF key, k_prf, for this file */
	if(!RAND_bytes(k_prf, CPOR_PRF_KEY_SIZE)) goto cleanup;
	

/*
	do{
		memset(buf, 0, CPOR_BLOCKSIZE);
		fread(buf, CPOR_BLOCKSIZE, 1, file);
		if(ferror(file)) goto cleanup;
		tag = cpor_tag_block(global, tag, buf, CPOR_BLOCKSIZE, index);
		if(!tag) goto cleanup;
		
		realloc(t0, t0_size + sizeof(BIGNUM));
		memcpy(t0 + t0_size, tag->alpha, sizeof(BIGNUM));
		t0_size += sizeof(BIGNUM);
		
		if(!write_pdp_tag(tagfile, tag)) goto cleanup;
		index++;
		destroy_pdp_tag(tag);
	}while(!feof(file));
	*/
	
	/* Encrypt t0 */
	
	/* Authenticate t0 */
	
	if(k_prf) sfree(k_prf, CPOR_PRF_KEY_SIZE);
	if(t0) sfree(t0, t0_size);
	
cleanup:

	if(k_prf) sfree(k_prf, CPOR_PRF_KEY_SIZE);
	if(t0) sfree(t0, t0_size);
}