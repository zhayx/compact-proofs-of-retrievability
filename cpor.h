/* 
* cpor.h
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

#ifndef __CPOR_H__
#define __CPOR_H__

#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <string.h>
#include <limits.h>

#define CPOR_ZP_BITS 80 /* The size (in bits) of the prime that creates the field Z_p */

#define CPOR_PRF_KEY_SIZE 20 /* Size (in bytes) of an HMAC-SHA1 */

/* The sector size 1 byte smaller than the size of Zp so that it 
 * is guaranteed to be an element of the group Zp */

#define CPOR_BLOCK_SIZE ((CPOR_ZP_BITS/8) - 1) /* Message block size in bytes */

#define CPOR_SECTOR_SIZE ((CPOR_ZP_BITS/8) - 1) /* Message sector size in bytes */

#define CPOR_NUM_SECTORS ( (CPOR_BLOCK_SIZE/CPOR_SECTOR_SIZE) + ((CPOR_BLOCK_SIZE % CPOR_SECTOR_SIZE) ? 1 : 0) ) /* Number of sectors per block */

/* Global settings */
typedef struct CPOR_global_struct CPOR_global;

struct CPOR_global_struct{
	BIGNUM *Zp;				/* The prime p that defines the field Zp */
};

/* This is the client's secret key */
typedef struct CPOR_key_struct CPOR_key;

struct CPOR_key_struct{
	unsigned char *k_enc;	/* The user's secret encryption key */
	unsigned char *k_mac;	/* The user's secret MAC key */
};

typedef struct CPOR_tag_struct CPOR_tag;

struct CPOR_tag_struct{
	BIGNUM *sigma;			/* The resulting authenticator, sigma_i*/
	unsigned int index;		/* The index for the authenticator, i */
};

typedef struct CPOR_challenge_struct CPOR_challenge;

struct CPOR_challenge_struct{

	unsigned int l;			/* The number of elements to be tested */
	unsigned int *I;		/* An array of l indicies to be tested */
	BIGNUM **nu;			/* An array of l random elements */
	
};

typedef struct CPOR_proof_struct CPOR_proof;

struct CPOR_proof_struct{
	BIGNUM *sigma;
	BIGNUM **mu;
};

/* Core CPOR functions from cpor-core.c */
CPOR_global *cpor_create_global(unsigned int bits);

CPOR_tag *cpor_tag_block(CPOR_global *global, unsigned char *k_prf, BIGNUM **alpha, unsigned char *block, size_t blocksize, unsigned int index);

CPOR_challenge *cpor_create_challenge(CPOR_global *global, unsigned int n);

CPOR_proof *cpor_create_proof_update(CPOR_global *global, CPOR_challenge *challenge, CPOR_proof *proof, CPOR_tag *tag, unsigned char *block, size_t blocksize, unsigned int i);

int cpor_verify_proof(CPOR_global *global, CPOR_proof *proof, CPOR_challenge *challenge, CPOR_tag *tag, unsigned char *k_prf, BIGNUM **alpha);

/* Helper functions from cpor-misc.c */

void sfree(void *ptr, size_t size);

int get_rand_range(unsigned int min, unsigned int max, unsigned int *value);

BIGNUM *generate_prf_i(unsigned char *key, unsigned int index);

CPOR_proof *allocate_cpor_proof();
void destroy_cpor_proof(CPOR_proof *proof);

void destroy_cpor_challenge(CPOR_challenge *challenge);
CPOR_challenge *allocate_cpor_challenge(unsigned int l);

void destroy_cpor_tag(CPOR_tag *tag);
CPOR_tag *allocate_cpor_tag();

void destroy_cpor_global(CPOR_global *global);
CPOR_global *allocate_cpor_global();

#endif