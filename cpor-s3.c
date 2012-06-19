/* 
* cpor-s3.c
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

#ifdef USE_S3

#include "cpor.h"
#include <libs3.h>

#define S3_BUCKET_NAME ""
#define S3_ACCESS_KEY ""
#define S3_SECRET_ACCESS_KEY "" 


struct buffer_pointer{

	unsigned char *buf;
	int offset;
};

static int putObjectDataCallback(int bufferSize, char *buffer, void *callbackData)
{
	int ret = 0;

	ret = fread(buffer, 1, params.block_size, callbackData);

	return ret;
	
}

static S3Status getObjectDataCallbackFile(int bufferSize, const char *buffer, void *callbackData)
{

    FILE *outfile = (FILE *) callbackData;

    size_t wrote = fwrite(buffer, 1, bufferSize, outfile);
    
    return ((wrote < (size_t) bufferSize) ? 
            S3StatusAbortedByCallback : S3StatusOK);

}

static S3Status getObjectDataCallback(int bufferSize, const char *buffer, void *callbackData)
{

	struct buffer_pointer *bp = callbackData;

	memcpy((char *)bp->buf + bp->offset, (char *)buffer, bufferSize);
	bp->offset += bufferSize;
	
	return S3StatusOK;
}

static S3Status responsePropertiesCallback(const S3ResponseProperties *properties, void *callbackData){         

	return S3StatusOK; 
}


static void responseCompleteCallback(S3Status status, const S3ErrorDetails *error, void *callbackData){ }


static int cpor_s3_get_block(char *filepath, size_t filepath_len, unsigned char *block, size_t block_len, unsigned int index){

	if(!filepath || !filepath_len || !block || !block_len) return 0;
	
	S3Status status;
    if ((status = S3_initialize("s3", S3_INIT_ALL))
        != S3StatusOK) {
        fprintf(stderr, "Failed to initialize libs3: %s\n", 
                S3_get_status_name(status));
        exit(-1);
    }

	S3BucketContext bucketContext =
    {
        S3_BUCKET_NAME, //bucket name
        S3ProtocolHTTPS,
        S3UriStylePath,
        S3_ACCESS_KEY, //access key
        S3_SECRET_ACCESS_KEY //secret access key
    };

    S3GetConditions getConditions =
    {
        -1, //ifModifiedSince,
        -1, // ifNotModifiedSince,
        0, //ifMatch,
        0 //ifNotMatch
    };

    S3GetObjectHandler getObjectHandler =
    {
        { &responsePropertiesCallback, &responseCompleteCallback },
        &getObjectDataCallback
    };

	struct buffer_pointer bp;
	bp.buf = block;
	bp.offset = 0;

	S3_get_object(&bucketContext, filepath, &getConditions, (index * block_len), block_len, 0, &getObjectHandler, &bp);

	S3_deinitialize();

	return 1;
	
	
}

int cpor_s3_put_file(char *filepath, size_t filepath_len){
	
	FILE *file = NULL;
	unsigned char buffer[params.block_size];
	struct stat statbuf;
	
	if(!filepath || !filepath_len) return 0;
	
	memset(buffer, 0, params.block_size);
	
	file = fopen(filepath, "r");
	if(file == NULL){
		printf("Couldn't open file %s\n", filepath);
		return -1;
	}
	
	/* Initialize the S3 library */
	S3Status status;
    if ((status = S3_initialize("s3", S3_INIT_ALL)) != S3StatusOK) {
        fprintf(stderr, "Failed to initialize libs3: %s\n", S3_get_status_name(status));
		goto cleanup;
    }
	
	/* Set the S3 context */
	S3BucketContext bucketContext =
    {
        S3_BUCKET_NAME,
        S3ProtocolHTTPS,
        S3UriStylePath,
        S3_ACCESS_KEY,
        S3_SECRET_ACCESS_KEY
    };

	/* Set the object properties */
    S3PutProperties putProperties =
    {
        0, //content-type defaults to "binary/octet-stream"
        0, //md5 sum, not required
        0, //cacheControl, not required
        0, //contentDispositionFilename, This is only relevent for objects which are intended to be shared to users via web browsers and which is additionally intended to be downloaded rather than viewed.
        0, //contentEncoding, This is only applicable to encoded (usually, compressed) content, and only relevent if the object is intended to be downloaded via a browser.
        (int64_t)-1,  //expires, This information is typically only delivered to users who download the content via a web browser.
        S3CannedAclPrivate,
        0, //metaPropertiesCount, This is the number of values in the metaData field.
        0 //metaProperties
    };

	/* Set the callbacks */
    S3PutObjectHandler putObjectHandler =
    {
        { &responsePropertiesCallback, &responseCompleteCallback },
        &putObjectDataCallback
    };

	/* Get the file size */
	if (stat(filepath, &statbuf) == -1) {
		fprintf(stderr, "\nERROR: Failed to stat file %s: ", filepath);
		goto cleanup;
	}

	S3_put_object(&bucketContext, filepath, statbuf.st_size, &putProperties, 0, &putObjectHandler, file);

	S3_deinitialize();
	if(file) fclose(file);
	
	return 1;

cleanup:
	if(file) fclose(file);
	S3_deinitialize();
	
	return 0;
}

int cpor_s3_get_file(char *filepath, size_t filepath_len){

	FILE *file = NULL;

	if(!filepath || !filepath_len) return 0;
	
	file = fopen(filepath, "w");
	if(!file){
		fprintf(stderr, "ERROR: Was not able to create %s.\n", filepath);
		goto cleanup;
	}
	
	S3Status status;
    if ((status = S3_initialize("s3", S3_INIT_ALL))
        != S3StatusOK) {
        fprintf(stderr, "Failed to initialize libs3: %s\n", 
                S3_get_status_name(status));
        exit(-1);
    }

	S3BucketContext bucketContext =
    {
        S3_BUCKET_NAME,
        S3ProtocolHTTPS,
        S3UriStylePath,
        S3_ACCESS_KEY,
        S3_SECRET_ACCESS_KEY
    };

    S3GetConditions getConditions =
    {
        -1, //ifModifiedSince,
        -1, // ifNotModifiedSince,
        0, //ifMatch,
        0 //ifNotMatch
    };

    S3GetObjectHandler getObjectHandler =
    {
        { &responsePropertiesCallback, &responseCompleteCallback },
        &getObjectDataCallbackFile
    };

	S3_get_object(&bucketContext, filepath, &getConditions, 0, 0, 0, &getObjectHandler, file);

	S3_deinitialize();
	if(file) fclose(file);

	return 1;

cleanup:	
	if(file) fclose(file);
	return 0;
}


CPOR_proof *cpor_s3_prove_file(char *filepath, size_t filepath_len, char *tagfilepath, size_t tagfilepath_len, CPOR_challenge *challenge){

	CPOR_tag *tag = NULL;
	CPOR_proof *proof = NULL;
	FILE *tagfile = NULL;
	char realtagfilepath[MAXPATHLEN];
	unsigned char block[params.block_size];
	int i = 0;
	
	if(!filepath || !challenge) return 0;
	if(filepath_len >= MAXPATHLEN) return 0;
	if(tagfilepath_len >= MAXPATHLEN) return 0;
	
	memset(realtagfilepath, 0, MAXPATHLEN);	
	
	/* If no tag file path is specified, add a .tag extension to the filepath */
	if(!tagfilepath && (filepath_len < MAXPATHLEN - 5)){
		if( snprintf(realtagfilepath, MAXPATHLEN, "%s.tag", filepath) >= MAXPATHLEN) goto cleanup;
	}else{
		memcpy(realtagfilepath, tagfilepath, tagfilepath_len);
	}
	
	/* Open the tag file for reading */
	tagfile = fopen(realtagfilepath, "r");
	if(!tagfile){
		fprintf(stderr, "ERROR: Was unable to open %s\n", realtagfilepath);
		return 0;
	}
	
	for(i = 0; i < challenge->l; i++){
		memset(block, 0, params.block_size);
	
		/* Get file block at I[i] from S3 */
		if(!cpor_s3_get_block(filepath, filepath_len, block, params.block_size, challenge->I[i])){ fprintf(stderr, "Error reading block %d from S3.\n", challenge->I[i]); goto cleanup; }
		
		/* Read tag for data block at I[i] */
		tag = read_cpor_tag(tagfile, challenge->I[i]);
		if(!tag){ fprintf(stderr, "Error reading tag.\n"); goto cleanup; }
		
		proof = cpor_create_proof_update(challenge, proof, tag, block, params.block_size, challenge->I[i], i);
		if(!proof){ fprintf(stderr, "Error generating proof.\n"); goto cleanup; }
		
		destroy_cpor_tag(tag);
		
	}
	
	proof = cpor_create_proof_final(proof);
	
	if(tagfile) fclose(tagfile);

	return proof;

cleanup:
	if(tagfile) fclose(tagfile);
	if(proof) destroy_cpor_proof(proof);
	if(tag) destroy_cpor_tag(tag);

	return NULL;
}

#endif