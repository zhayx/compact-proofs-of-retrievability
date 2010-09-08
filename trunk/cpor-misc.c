/* 
* cpor-misc.c
*
* Copyright (c) 2008, Zachary N J Peterson <znpeters@nps.edu>
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*     * Redistributions of source code must retain the above copyright
*       notice, this list of conditions and the following disclaimer.
*     * Redistributions in binary form must reproduce the above copyright
*       notice, this list of conditions and the following disclaimer in the
*       documentation and/or other materials provided with the distribution.
*     * Neither the name of the <organization> nor the
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

void sfree(void *ptr, size_t size){ memset(ptr, 0, size); free(ptr); ptr = NULL;}

int get_rand_range(unsigned int min, unsigned int max, unsigned int *value){
	unsigned int rado;
	unsigned int range = max - min + 1;
	
	if(!value) return 0;
	if(max < min) return 0;
	do{
		if(!RAND_bytes((unsigned char *)&rado, sizeof(unsigned int))) return 0;
	}while(rado > UINT_MAX - (UINT_MAX % range));
	
	*value = min + (rado % range);
	
	return 1;
}

/* gereate_prf_i: the implementation of the pseudo-random funcation f_k(i).  It takes in
 * the MAC key key and a block index.
 * It returns an allocated BIGNUM containing the resulting PRF or NULL on failure.
 * In this implementation we use HMAC-SHA1.
 */
BIGNUM *generate_prf_i(unsigned char *key, unsigned int index){
	
	unsigned char *prf_result = NULL;
	size_t prf_result_size = 0;
	BIGNUM *prf_result_bn = NULL;
	
	if(!key) return NULL;
	
	/* Allocate memory */
	if( ((prf_result = malloc(EVP_MAX_MD_SIZE)) == NULL)) goto cleanup;
	memset(prf_result, 0, EVP_MAX_MD_SIZE);
	if( ((prf_result_bn = BN_new()) == NULL)) goto cleanup;
	
	/* Do the HMAC-SHA1 */
	if(!HMAC(EVP_sha1(), key, CPOR_PRF_KEY_SIZE, (unsigned char *)&index, sizeof(unsigned int),
		prf_result, (unsigned int *)&prf_result_size)) goto cleanup;
		
	/* Convert PRF result into a BIGNUM */
	prf_result_bn = BN_bin2bn(prf_result, prf_result_size, NULL);
	if(!prf_result_bn) goto cleanup;
	
	/* Free some memory */
	if(prf_result) sfree(prf_result, EVP_MAX_MD_SIZE);	
	
	return prf_result_bn;
	
cleanup:
	if(prf_result) sfree(prf_result, EVP_MAX_MD_SIZE);
	if(prf_result_bn) BN_clear_free(prf_result_bn);
	return NULL;
	
}

int cpor_verify_key(CPOR_key *key){

	if(!key->k_enc) return 0;
	if(!key->k_mac) return 0;
	
	return 1;
}

void destroy_cpor_global(CPOR_global *global){

	if(!global) return;
	if(global->Zp) BN_clear_free(global->Zp);
	sfree(global, sizeof(CPOR_global));
	
	return;
}

CPOR_global *allocate_cpor_global(){

	CPOR_global *global = NULL;
	
	if( ((global = malloc(sizeof(CPOR_global))) == NULL)) return NULL;
	if( ((global->Zp = BN_new()) == NULL)) goto cleanup;

	return global;
	
cleanup:
	destroy_cpor_global(global);
	return NULL;
}

void destroy_cpor_challenge(CPOR_challenge *challenge){

	int i;

	if(!challenge) return;
	if(challenge->I) sfree(challenge->I, sizeof(unsigned int) * challenge->l);
	if(challenge->nu){
		for(i = 0; i < challenge->l; i++){
			if(challenge->nu[i]) BN_clear_free(challenge->nu[i]);
		}
		sfree(challenge->nu, sizeof(BIGNUM *) * challenge->l);
	}
	challenge->l = 0;
	sfree(challenge, sizeof(CPOR_challenge));
	
	return;
}

CPOR_challenge *allocate_cpor_challenge(unsigned int l){
	
	CPOR_challenge *challenge = NULL;
	int i = 0;

	if( ((challenge = malloc(sizeof(CPOR_challenge))) == NULL)) return NULL;
	memset(challenge, 0, sizeof(CPOR_challenge));
	challenge->l = l;
	if( ((challenge->I = malloc(sizeof(unsigned int) * challenge->l)) == NULL)) goto cleanup;
	memset(challenge->I, 0, sizeof(unsigned int) * challenge->l);
	if( ((challenge->nu = malloc(sizeof(BIGNUM *) * challenge->l)) == NULL)) goto cleanup;	
	memset(challenge->nu, 0, sizeof(BIGNUM *) * challenge->l);
	for(i = 0; i < challenge->l; i++)
		if( ((challenge->nu[i] = BN_new()) == NULL)) goto cleanup;
	

	return challenge;
	
cleanup:
	destroy_cpor_challenge(challenge);
	return NULL;
}


void destroy_cpor_tag(CPOR_tag *tag){

	if(!tag) return;
	if(tag->sigma) BN_clear_free(tag->sigma);
	sfree(tag, sizeof(CPOR_tag));
	tag = NULL;
}

CPOR_tag *allocate_cpor_tag(){

	CPOR_tag *tag = NULL;
	
	if( ((tag = malloc(sizeof(CPOR_tag))) == NULL)) return NULL;
	memset(tag, 0, sizeof(CPOR_tag));
	if( ((tag->sigma = BN_new()) == NULL)) goto cleanup;
	tag->index = 0;
	
	return tag;
	
cleanup:
	if(tag) destroy_cpor_tag(tag);
	return NULL;
	
}

void destroy_cpor_proof(CPOR_proof *proof){

	int i = 0;

	if(!proof) return;
	if(proof->sigma) BN_clear_free(proof->sigma);
	if(proof->mu){
		for(i = 0; i < CPOR_NUM_SECTORS; i++){
			if(proof->mu[i]) BN_clear_free(proof->mu[i]);
		}
		sfree(proof->mu, sizeof(BIGNUM *) * CPOR_NUM_SECTORS);
	}
	sfree(proof, sizeof(CPOR_proof));

	return;	
}

CPOR_proof *allocate_cpor_proof(){

	CPOR_proof *proof = NULL;
	int i = 0;
		
	if( ((proof = malloc(sizeof(CPOR_proof))) == NULL)) return NULL;
	memset(proof, 0, sizeof(CPOR_proof));
	if( ((proof->sigma = BN_new()) == NULL )) goto cleanup;
	if( ((proof->mu = malloc(sizeof(BIGNUM *) * CPOR_NUM_SECTORS)) == NULL)) goto cleanup;
	memset(proof->mu, 0, sizeof(BIGNUM *) * CPOR_NUM_SECTORS);
	for(i = 0; i < CPOR_NUM_SECTORS; i++)
		if( ((proof->mu[i] = BN_new()) == NULL)) goto cleanup;

	return proof;

cleanup:
	destroy_cpor_proof(proof);
	return NULL;	

	
}