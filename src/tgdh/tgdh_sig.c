/* CLIQUES Non-Commercial License (covers BD, CLQ, STR and TGDH
libraries).  Copyright (c) 1998-2002 by the University of California,
Irvine.  All rights reserved.

Permission to use, copy, modify, and distribute this software and its
documentation in source and binary forms for lawful non-commercial
purposes and without fee is hereby granted, provided that the above
copyright notice appear in all copies and that both the copyright
notice and this permission notice appear in supporting documentation,
and that any documentation, advertising materials, and other materials
related to such distribution and use acknowledge that the software was
developed by the University of California, Irvine, Information and
Computer Science Department. The name of University of California,
Irvine may not be used to endorse or promote products derived from
this software without specific prior written permission.

THE UNIVERSITY OF CALIFORNIA, IRVINE MAKES NO REPRESENTATIONS ABOUT
THE SUITABILITY OF THIS SOFTWARE FOR ANY PURPOSE.  THIS SOFTWARE IS
PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND
NON-INFRINGEMENT.

IN NO EVENT SHALL UNIVERSITY OF CALIFORNIA, IRVINE OR ANY OTHER
CONTRIBUTOR BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL
DAMAGES, WHETHER IN CONTRACT, TORT, OR OTHER FORM OF ACTION, ARISING
OUT OF OR IN CONNECTION WITH, THE USE OR PERFORMANCE OF THIS SOFTWARE.

All questions concerning this software should be directed to
cliques@ics.uci.edu. */

/*********************************************************************
 * tgdh_sig.c (copy of tgdh_sig.c)                                   * 
 * TREE signature source file.                                       * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/
#include <memory.h>

//#include "openssl/evp.h"
//#include "openssl/x509.h"

#include "tgdh_api.h"
#include "error.h"
#include "common.h"
#include "tgdh_sig.h"
#include "../sig/sig_algs_internal.h"
#include "../sig/sig_algs.h"
#include "../openssl/x509.h"
#ifdef SIG_TIMING
#include "tgdh_api_misc.h" /* tgdh_get_time is defined here */
#endif

/* dmalloc CNR.  */
#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif

#define MAX_BUF_LEN     8192
#define HDR_MAGIC        0x34215609


/* tgdh_sign_message: It signs the token using the current user public
 * key scheme. The signature will be appended to the begining of the
 * input token
 */
int tgdh_sign_message(TGDH_CONTEXT *ctx, CLQ_TOKEN *input, ec_key_pair key_pair, const char *hdr_type, const char *version) 
{
  int ret=OK;
  //EVP_MD_CTX *md_ctx=NULL;
  unsigned int sig_len=0;
  unsigned int pkey_len=0;
  clq_uchar *data=NULL;
  unsigned int pos=0;
  hash_alg_type hash_type;
  ec_sig_alg_type sig_type;
  struct ec_sign_context sig_ctx;
  metadata_hdr hdr;
  u8 sig[EC_MAX_SIGLEN];
  u8 siglen;
#ifdef SIG_TIMING
  double Time=0.0;

  Time=tgdh_get_time();
#endif

  if (ctx==(TGDH_CONTEXT *)NULL) {ret=CTX_ERROR; goto error;}
  if (input==(CLQ_TOKEN*) NULL){
    fprintf(stderr, "TOKEN NULL=sign\n");
    ret=INVALID_INPUT_TOKEN;
    goto error;
  }
//  md_ctx=(EVP_MD_CTX *) malloc(sizeof(EVP_MD_CTX));
//  if (md_ctx == NULL) {ret=MALLOC_ERROR; goto error;}
//  pkey_len=EVP_PKEY_size(ctx->pkey);
  data=(clq_uchar *) malloc (pkey_len+(input->length)+TOTAL_INT);

//  if (ctx->pkey->type == EVP_PKEY_RSA)
//    EVP_SignInit (md_ctx, RSA_MD());
//  else if (ctx->pkey->type == EVP_PKEY_DSA)
//    EVP_SignInit (md_ctx, DSA_MD());
//  else {
//    ret=INVALID_SIGNATURE_SCHEME;
//    goto error;
//  }
//
//  EVP_SignUpdate (md_ctx, input->t_data, input->length);
//
//  /* Encoding size of the signature (an integer), the signature
//     ittgdh, and then the data */
//  ret = EVP_SignFinal (md_ctx, data+TOTAL_INT, &sig_len, ctx->pkey);
//  if (ret == 0) {
//#ifdef SIG_DEBUG
//    ERR_print_errors_fp (stderr);
//#endif
//    ret=SIGNATURE_ERROR;
//    goto error;
//  }
  //
  ret = ec_sign_init(&sig_ctx, &key_pair, sig_type, hash_type);
  if((hdr_type != NULL) && (version != NULL)){
		ret = ec_sign_update(&sig_ctx, (const u8 *)&hdr, sizeof(metadata_hdr));
		if (ret) {
			printf("Error: error when signing\n");
			goto error;
		}
	}
  ret = ec_sign_finalize(&sig_ctx, sig, siglen);
	if (ret) {
		printf("Error: error when signing\n");
		goto error;
	}

  //
  ret = OK;

  int_encode (data,&pos,sig_len);
  if (pos != TOTAL_INT) { ret=ERROR_INT_DECODE; goto error; }


  memcpy (data+sig_len+pos,input->t_data,input->length);
  
  free(input->t_data);
  input->t_data=data;
  input->length+=sig_len+pos;

 error:

  //if (md_ctx != NULL) free (md_ctx);
  if (ret != OK) free(data);

#ifdef SIG_TIMING
  Time=tgdh_get_time()-Time;
  tgdh_print_times("tgdh_sign_message",Time); 
#endif

  return ret;                                                        
}

int tgdh_vrfy_sign(TGDH_CONTEXT *ctx, TGDH_CONTEXT *new_ctx,
                   CLQ_TOKEN *input, CLQ_NAME *member_name,
				   TGDH_SIGN *sign, ec_params *params, const char *in_sig_fname)
{ 
	int ret=OK;
	//EVP_MD_CTX *md_ctx=NULL;
	//EVP_PKEY *pubkey=NULL; /* will not to the public key of member_name */
	KEY_TREE *tmp_tree=NULL;
	u8 st_sig[EC_STRUCTURED_SIG_EXPORT_SIZE(EC_MAX_SIGLEN)];
	u8 stored_curve_name[MAX_CURVE_NAME_LEN];
	u8 pub_key_buf[EC_STRUCTURED_PUB_KEY_MAX_EXPORT_SIZE];
	struct ec_verify_context verif_ctx;
	ec_sig_alg_type stored_sig_type;
	hash_alg_type stored_hash_type;
	const ec_str_params *ec_str_p;
	ec_sig_alg_type sig_type;
	hash_alg_type hash_type;
	u8 sig[EC_MAX_SIGLEN];
	u8 siglen, st_siglen;
	size_t read, to_read;
	u8 buf[MAX_BUF_LEN];
	u8 pub_key_buf_len;
	size_t raw_data_len;
	ec_pub_key pub_key;
	//ec_params params;
	metadata_hdr *hdr;
	size_t exp_len;

#ifdef SIG_TIMING
	double Time=0.0;
	Time=tgdh_get_time();
#endif

	if (ctx==(TGDH_CONTEXT *)NULL) {ret=CTX_ERROR; goto error;}
	if (new_ctx==(TGDH_CONTEXT *)NULL) {ret=CTX_ERROR; goto error;}
	if (input==(CLQ_TOKEN*) NULL)
	{
		fprintf(stderr, "TOKEN NULL=vrfy\n");
		ret=INVALID_INPUT_TOKEN;
		goto error;
	}
	if (sign==(TGDH_SIGN*) NULL) {ret=INVALID_SIGNATURE; goto error;}
	//md_ctx=(EVP_MD_CTX *) malloc(sizeof(EVP_MD_CTX));
	//if (md_ctx == NULL) {ret=MALLOC_ERROR; goto error;}

	/* Searching for the member and obtainig the public key if needed */
	tmp_tree=tgdh_search_member(new_ctx->root, 4, member_name);
	if (tmp_tree==NULL) 
	{
		ret=MEMBER_NOT_IN_GROUP; goto error;
	}

	if (tmp_tree->tgdh_nv->member->cert==NULL) 
	{
		tmp_tree->tgdh_nv->member->cert=clq_get_cert(member_name);
		if (tmp_tree->tgdh_nv->member->cert == NULL) 
		{ret=INVALID_MEMBER_NAME; goto error;}
	}

//	MUST_HAVE(ec_name != NULL);
//
//	/************************************/
//	/* Get parameters from pretty names */
//	if (string_to_params(ec_name, ec_sig_name, &sig_type, &ec_str_p,
//	hash_algorithm, &hash_type)) 
//	{
//		goto error;
//	}
	/* Import the parameters */
	import_params(params, ec_str_p);

	ret = ec_get_sig_len(params, sig_type, hash_type, &siglen);
	if (ret) 
	{
		printf("Error getting effective signature length from %s\n",
			   (const char *)(ec_str_p->name->buf));
		goto error;
	}
	//pub_key=tmp_tree->tgdh_nv->member->cert->cert_info->key);
	pub_key_buf_len = EC_STRUCTURED_PUB_KEY_EXPORT_SIZE(&(tmp_tree->tgdh_nv->member->cert->cert_info->key));
	ret = ec_structured_pub_key_import_from_buf(tmp_tree->tgdh_nv->member->cert->cert_info->key, &params,
						pub_key_buf,
						pub_key_buf_len, sig_type);
	if (ret) 
	{
		printf("Error: error when importing public key from %s\n");
		goto error;
	}

	if (in_sig_fname == NULL) 
	{
	/* ... and first read metadata header */
		hdr=ctx->hdr;	
	/* Sanity checks on the header we get */
		if (hdr->magic != HDR_MAGIC) 
		{
			printf("Error: got magic 0x%08x instead of 0x%08x "
				   "from metadata header\n", hdr->magic, HDR_MAGIC);
			goto error;
		}

		st_siglen = EC_STRUCTURED_SIG_EXPORT_SIZE(siglen);
		MUST_HAVE(raw_data_len > (sizeof(hdr) + st_siglen));
		exp_len = raw_data_len - sizeof(hdr) - st_siglen;
		if (hdr->len != exp_len) {
			printf("Error: got raw size of %u instead of %lu from "
				   "metadata header\n", hdr->len,
				   (unsigned long)exp_len);
			goto error;
		}

		if (hdr->siglen != st_siglen) {
			printf("Error: got siglen %u instead of %d from "
				   "metadata header\n", hdr->siglen, siglen);
			goto error;
		}

		/* Dump the header */
		dump_hdr_info(&hdr);

		/*
		 * We now need to seek in file to get structured signature.
		 * Before doing that, let's first check size is large enough.
		 */
		if (raw_data_len < (sizeof(hdr) + st_siglen)) 
		{
			goto error;
		}

	/* Import the signature from the structured signature buffer */
		ret = ec_structured_sig_import_from_buf(sig, siglen,
												st_sig, st_siglen,
												&stored_sig_type,
												&stored_hash_type,
												stored_curve_name);
		if (ret) 
		{
			printf("Error: error when importing signature ");
			goto error;
		}
		if (!are_str_equal((char *)stored_curve_name,
			   (char *)params->curve_name)) 
		{
			printf("Error: curve type '%s' imported from signature "
				   "mismatches with '%s'\n", stored_curve_name,
				   params->curve_name);
			goto error;
		}

		dump_hdr_info(&hdr);
		ret = ec_structured_sig_import_from_buf(sig, siglen,
						st_sig, st_siglen,
						&stored_sig_type,
						&stored_hash_type,
						stored_curve_name);
		if (ret) 
		{
			printf("Error: error when importing signature ");
			goto error;
		}
		if (stored_sig_type != sig_type) 
		{
			printf("Error: signature type imported from signature "
				   "mismatches with\n");
			goto error;
		}
		if (stored_hash_type != hash_type) 
		{
			printf("Error: hash algorithm type imported from "
				   "signature mismatches with\n");
			goto error;
		}
		if (!are_str_equal((char *)stored_curve_name,
			   (char *)params->curve_name)) 
		{
			printf("Error: curve type '%s' imported from signature "
				   "mismatches with '%s'\n", stored_curve_name,
				   params->curve_name);
			goto error;
		}
		exp_len += sizeof(hdr);
	} 
	else 
	{
		/* Read the raw signature from the signature file */
		exp_len = raw_data_len;
	}

	ret = ec_verify_init(&verif_ctx, &pub_key, sig, siglen,
						 sig_type, hash_type);
	if (ret) {
		goto error;
	}
	ret = ec_verify_update(&verif_ctx, buf, (u32)read);

	if (ret == 0) 
	{
		#ifdef SIG_DEBUG
		ERR_print_errors_fp (stderr);
		#endif
		ret=SIGNATURE_DIFER;
		goto error;
	}
	ret = ec_verify_finalize(&verif_ctx);
	if (ret) 
	{
		goto error;
	}
	ret = OK;

error:

//  if (md_ctx != NULL) free (md_ctx);

#ifdef SIG_TIMING
  Time=tgdh_get_time()-Time;
  tgdh_print_times("tgdh_vrfy_sign",Time); 
#endif

  return ret;
}

int tgdh_remove_sign(CLQ_TOKEN *input, TGDH_SIGN **sign) {
  unsigned int pos=0;
  int ret=OK;
  TGDH_SIGN *signature=*sign;

  if (input == (CLQ_TOKEN*) NULL){
    fprintf(stderr, "TOKEN NULL:remove\n");
    return INVALID_INPUT_TOKEN;
  }
  
  if (signature == (TGDH_SIGN*) NULL) {
    signature=(TGDH_SIGN*) malloc (sizeof(TGDH_SIGN));
    if (signature == (TGDH_SIGN*) NULL) return MALLOC_ERROR;
  }

  int_decode (input,&pos,&(signature->length));
  /* Need when restoring the signature in token tgdh_restore_sign */
  if (pos != TOTAL_INT) {ret=ERROR_INT_DECODE; goto error; }
  if (signature->length+pos > input->length) {
    fprintf(stderr, "length+pos\n");
    ret=INVALID_INPUT_TOKEN;
    goto error;
  }
  /* No new memory is mallocated just pointers moved around !! */
  signature->signature=input->t_data+pos;
  input->t_data+=signature->length+pos;
  input->length-=signature->length+pos;

  *sign=signature;
  signature=NULL;
 error:

  if (ret!=OK)
    /* If we mallocate the memory, then let's free it */
    if ((*sign==(TGDH_SIGN*)NULL) && (signature != NULL))
      free (signature);
  
  return ret;
}

int tgdh_restore_sign(CLQ_TOKEN *input, TGDH_SIGN **signature) {
  int ret=OK;
  TGDH_SIGN *sign=*signature;
  
  if (input == (CLQ_TOKEN*) NULL){
    fprintf(stderr, "NULL TOKEN: restore\n");
    return INVALID_INPUT_TOKEN;
  }
  
  if (*signature == (TGDH_SIGN*) NULL) return ret;
  if (input->length+sign->length+TOTAL_INT > MSG_SIZE){
    fprintf(stderr, "size\n");
    return INVALID_INPUT_TOKEN;
  }

  /* No memory needs to be free see tgdh_remove_sign ! */
  input->length+=sign->length+TOTAL_INT;
  input->t_data-=sign->length+TOTAL_INT;

  sign->length=0;
  sign->signature=NULL;
  free (*signature);
  *signature=NULL;

  return ret;
}
