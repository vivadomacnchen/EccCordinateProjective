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
#ifdef SIG_TIMING
#include "tgdh_api_misc.h" /* tgdh_get_time is defined here */
#endif

/* dmalloc CNR.  */
#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif


/* tgdh_sign_message: It signs the token using the current user public
 * key scheme. The signature will be appended to the begining of the
 * input token
 */
int tgdh_sign_message(TGDH_CONTEXT *ctx, CLQ_TOKEN *input) {
  int ret=OK;
  EVP_MD_CTX *md_ctx=NULL;
  unsigned int sig_len=0;
  unsigned int pkey_len=0;
  clq_uchar *data=NULL;
  unsigned int pos=0;
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
  md_ctx=(EVP_MD_CTX *) malloc(sizeof(EVP_MD_CTX));
  if (md_ctx == NULL) {ret=MALLOC_ERROR; goto error;}
  pkey_len=EVP_PKEY_size(ctx->pkey);
  data=(clq_uchar *) malloc (pkey_len+(input->length)+TOTAL_INT);

  if (ctx->pkey->type == EVP_PKEY_RSA)
    EVP_SignInit (md_ctx, RSA_MD());
  else if (ctx->pkey->type == EVP_PKEY_DSA)
    EVP_SignInit (md_ctx, DSA_MD());
  else {
    ret=INVALID_SIGNATURE_SCHEME;
    goto error;
  }

  EVP_SignUpdate (md_ctx, input->t_data, input->length);

  /* Encoding size of the signature (an integer), the signature
     ittgdh, and then the data */
  ret = EVP_SignFinal (md_ctx, data+TOTAL_INT, &sig_len, ctx->pkey);
  if (ret == 0) {
#ifdef SIG_DEBUG
    ERR_print_errors_fp (stderr);
#endif
    ret=SIGNATURE_ERROR;
    goto error;
  }
  ret = OK;

  int_encode (data,&pos,sig_len);
  if (pos != TOTAL_INT) { ret=ERROR_INT_DECODE; goto error; }


  memcpy (data+sig_len+pos,input->t_data,input->length);
  
  free(input->t_data);
  input->t_data=data;
  input->length+=sig_len+pos;

 error:

  if (md_ctx != NULL) free (md_ctx);
  if (ret != OK) free(data);

#ifdef SIG_TIMING
  Time=tgdh_get_time()-Time;
  tgdh_print_times("tgdh_sign_message",Time); 
#endif

  return ret;                                                        
}

int tgdh_vrfy_sign(TGDH_CONTEXT *ctx, TGDH_CONTEXT *new_ctx,
                   CLQ_TOKEN *input, CLQ_NAME *member_name,
                   TGDH_SIGN *sign) 
{ 
  int ret=OK;
  EVP_MD_CTX *md_ctx=NULL;
  EVP_PKEY *pubkey=NULL; /* will not to the public key of member_name */
  KEY_TREE *tmp_tree=NULL;
#ifdef SIG_TIMING
  double Time=0.0;

  Time=tgdh_get_time();
#endif

  if (ctx==(TGDH_CONTEXT *)NULL) {ret=CTX_ERROR; goto error;}
  if (new_ctx==(TGDH_CONTEXT *)NULL) {ret=CTX_ERROR; goto error;}
  if (input==(CLQ_TOKEN*) NULL){
    fprintf(stderr, "TOKEN NULL=vrfy\n");
    ret=INVALID_INPUT_TOKEN;
    goto error;
  }
  if (sign==(TGDH_SIGN*) NULL) {ret=INVALID_SIGNATURE; goto error;}
  md_ctx=(EVP_MD_CTX *) malloc(sizeof(EVP_MD_CTX));
  if (md_ctx == NULL) {ret=MALLOC_ERROR; goto error;}

  /* Searching for the member and obtainig the public key if needed */
  tmp_tree=tgdh_search_member(new_ctx->root, 4, member_name);
  if (tmp_tree==NULL) {
    ret=MEMBER_NOT_IN_GROUP; goto error;
  }

  if (tmp_tree->tgdh_nv->member->cert==NULL) {
    tmp_tree->tgdh_nv->member->cert=clq_get_cert(member_name);
    if (tmp_tree->tgdh_nv->member->cert == NULL) 
      {ret=INVALID_MEMBER_NAME; goto error;}
  }

  if (tmp_tree->tgdh_nv->member->cert->cert_info->key->pkey==NULL) {
    if (X509_get_pubkey(tmp_tree->tgdh_nv->member->cert) == 
        (EVP_PKEY *) NULL) {ret=INVALID_PKEY; goto error; } 
  }

  pubkey=tmp_tree->tgdh_nv->member->cert->cert_info->key->pkey;
  if (pubkey->type == EVP_PKEY_RSA)
    EVP_VerifyInit (md_ctx, RSA_MD());
  else if (pubkey->type == EVP_PKEY_DSA)
    EVP_VerifyInit (md_ctx, DSA_MD());
  else {
    ret=INVALID_SIGNATURE_SCHEME;
    goto error;
  }

  EVP_VerifyUpdate (md_ctx, input->t_data, input->length);
  ret = EVP_VerifyFinal (md_ctx, sign->signature, sign->length, pubkey);
  if (ret == 0) {
#ifdef SIG_DEBUG
    ERR_print_errors_fp (stderr);
#endif
    ret=SIGNATURE_DIFER;
    goto error;
  }
  ret = OK;

 error:

  if (md_ctx != NULL) free (md_ctx);

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
