

#include "cpor.h"

int main(){
	
	CPOR_global *global = NULL;
	CPOR_tag * tag = NULL;
	CPOR_challenge *challenge = NULL;
	CPOR_proof *proof = NULL;
	BIGNUM **alpha = NULL;
	unsigned char k_prf[CPOR_PRF_KEY_SIZE];
	unsigned char block[CPOR_BLOCK_SIZE];
	int i;
	
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
	
	if(( i = cpor_verify_proof(global, proof, challenge, tag, k_prf, alpha)) == 1 ) printf("Verified!\n");
	else if (i == 0) printf("Cheating!\n");
	else printf("Error!\n");
	
	destroy_cpor_global(global);
	destroy_cpor_tag(tag);
	destroy_cpor_challenge(challenge);
	destroy_cpor_proof(proof);
	
	return 0;
	
}