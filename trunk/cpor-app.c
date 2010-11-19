/* 
* cpor-app.c
*
* Copyright (c) 2010, Zachary N J Peterson <znpeters@nps.edu>
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*     * Redistributions of source code must retain the above copyright
*       notice, this list of conditions and the following disclaimer.
*     * Redistributions in binary form must reproduce the above copyright
*       notice, this list of conditions and the following disclaimer in the
*       documentation and/or other materials provided with the distribution.
*     * Neither the name of the Naval Postgraduate School nor the
*       names of its contributors may be used to endorse or promote products
*       derived from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY ZACHARY N J PETERSON ``AS IS'' AND ANY
* EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL ZACHARY N J PETERSON BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "cpor.h"

int main(int argc, char **argv){
	
	CPOR_challenge *challenge = NULL;
	CPOR_proof *proof = NULL;
	int i = -1;
#ifdef USE_S3
	char tagfilepath[MAXPATHLEN];
	char tfilepath[MAXPATHLEN];
#endif	
	
	if(!argv[1]) return -1;
	
	//printf("Blocksize: %d bytes. Sector size: %d bytes. Num sectors per block: %d\n", CPOR_BLOCK_SIZE, CPOR_SECTOR_SIZE, CPOR_NUM_SECTORS);

	if(!cpor_create_new_keys()) printf("Couldn't create keys\n");

	fprintf(stdout, "Tagging %s...", argv[1]); fflush(stdout);
	if(!cpor_tag_file(argv[1], strlen(argv[1]), NULL, 0, NULL, 0)) printf("No tag\n");
	else printf("Done\n");
	
#ifdef USE_S3
	fprintf(stdout, "\tWriting file %s to S3...", argv[1]); fflush(stdout);
	if(!cpor_s3_put_file(argv[1], strlen(argv[1]))) printf("Couldn't write %s to S3.\n", argv[1]);
	else printf("Done.\n");
	
	memset(tagfilepath, 0, MAXPATHLEN);
	snprintf(tagfilepath, MAXPATHLEN, "%s.tag", argv[1]);
	fprintf(stdout, "\tWriting tag file %s to S3...", tagfilepath); fflush(stdout);
	if(!cpor_s3_put_file(tagfilepath, strlen(tagfilepath))) printf("Couldn't write %s to S3.\n", argv[1]);
	else printf("Done.\n");
	
	memset(tfilepath, 0, MAXPATHLEN);
	snprintf(tfilepath, MAXPATHLEN, "%s.t", argv[1]);
	fprintf(stdout, "\tWriting t file %s to S3...", tfilepath); fflush(stdout);
	if(!cpor_s3_put_file(tfilepath, strlen(tfilepath))) printf("Couldn't write %s to S3.\n", argv[1]);
	else printf("Done.\n");			
#endif	

	fprintf(stdout, "Challenging file %s...\n", argv[1]); fflush(stdout);				

#ifdef USE_S3
	printf("\tGetting tag file...");fflush(stdout);
	fflush(stdout);
	if(!cpor_s3_get_file(tagfilepath, strlen(tagfilepath))) printf("Cloudn't get tag file.\n");
	else printf("Done.\n");
	
	printf("\tGetting t file...");fflush(stdout);
	fflush(stdout);
	if(!cpor_s3_get_file(tfilepath, strlen(tfilepath))) printf("Cloudn't get t file.\n");
	else printf("Done.\n");
#endif

	fprintf(stdout, "\tCreating challenge for %s...", argv[1]); fflush(stdout);
	challenge = cpor_challenge_file(argv[1], strlen(argv[1]), NULL, 0);
	if(!challenge) printf("No challenge\n");
	else printf("Done.\n");

	fprintf(stdout, "\tComputing proof...");fflush(stdout);
#ifdef USE_S3
	proof = cpor_s3_prove_file(argv[1], strlen(argv[1]), NULL, 0, challenge);
#else	
	proof = cpor_prove_file(argv[1], strlen(argv[1]), NULL, 0, challenge);
#endif
	if(!proof) printf("No proof\n");
	else printf("Done.\n");

	printf("\tVerifying proof..."); fflush(stdout);		
	if((i = cpor_verify_file(argv[1], strlen(argv[1]), NULL, 0, challenge, proof)) == 1) printf("Verified\n");
	else if(i == 0) printf("Cheating!\n");
	else printf("Error\n");
	
	if(challenge) destroy_cpor_challenge(challenge);
	if(proof) destroy_cpor_proof(proof);
	
/*
	unsigned char k_prf[CPOR_PRF_KEY_SIZE];
	unsigned char block[CPOR_BLOCK_SIZE];
	CPOR_global *global = NULL;
	CPOR_tag *tag;
	BIGNUM **alpha = NULL;

	printf("Blocksize: %d Sector size: %d Num sectors: %d\n", CPOR_BLOCK_SIZE, CPOR_SECTOR_SIZE, CPOR_NUM_SECTORS);
	
	global = cpor_create_global(CPOR_ZP_BITS);
	if(!global) printf("No global\n");
	
	RAND_bytes(k_prf, CPOR_PRF_KEY_SIZE);
	RAND_bytes(block, CPOR_BLOCK_SIZE);
	
	alpha = malloc(sizeof(BIGNUM *) * CPOR_NUM_SECTORS);
	memset(alpha, 0, sizeof(BIGNUM *) * CPOR_NUM_SECTORS);
	
	for(i = 0; i < CPOR_NUM_SECTORS; i++){
		alpha[i] = BN_new();
		BN_rand_range(alpha[i], global->Zp);
	}
	
	tag = cpor_tag_block(global, k_prf, alpha, block, CPOR_BLOCK_SIZE, 0);
	if(!tag) printf("No tag\n");
	
	
	challenge = cpor_create_challenge(global, 1);
	if(!challenge) printf("No challenge\n");
		
	proof = cpor_create_proof_update(global, challenge, proof, tag, block, CPOR_BLOCK_SIZE, 0);
	if(!proof) printf("No proof\n");
	
	if(( i = cpor_verify_proof(global, proof, challenge, k_prf, alpha)) == 1 ) printf("Verified!\n");
	else if (i == 0) printf("Cheating!\n");
	else printf("Error!\n");
	
	for(i = 0; i < CPOR_NUM_SECTORS; i++){
		if(alpha[i]) BN_clear_free(alpha[i]);
	}
	sfree(alpha, sizeof(BIGNUM *) * CPOR_NUM_SECTORS);
	
	destroy_cpor_global(global);
	destroy_cpor_tag(tag);
	destroy_cpor_challenge(challenge);
	destroy_cpor_proof(proof);
*/
	
	
	return 0;
	
}