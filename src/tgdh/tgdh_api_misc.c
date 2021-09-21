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
 * tgdh_api_misc.c                                                   * 
 * TREE api miscellaneous source file.                               * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#include <stdio.h>
/* The next three are needed for creat() in tgdh_gen_params */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include <unistd.h>
#include <malloc.h>
//#include <math.h>

#ifdef TIMING
/* Needed by getrusgae */
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

int print=1;

#endif

/* SSL include files */
//#include "openssl/bio.h"
//#include "openssl/dsa.h"
//#include "openssl/bn.h"
//#include "openssl/rand.h"
//#include "openssl/md5.h"

/* TGDH_API include files */
#include "common.h"
#include "tgdh_api.h"
#include "tgdh_api_misc.h"


/* dmalloc CNR.  */
#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif

#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 32
#endif

#ifdef MEMCHECK
int number_malloc[length_memcheck];
int number_free[length_memcheck];
#endif

//int tgdh_print_dsa(TGDH_CONTEXT *ctx)
//{
//
//  return 0;
//}

//# ifndef OPENSSL_NO_FP_API
//int BN_print_fp(FILE *fp, const nn a)
//{
//
//}
//# endif

void tgdh_print_ctx(char *name, TGDH_CONTEXT *ctx)
{

  fprintf(ERR_STRM,"\n--- %s ---\n\t", name);
  if(ctx == NULL) {
    fprintf(ERR_STRM,"CTX for %s is null\t", name);
    return;
  }
  if(ctx->member_name != NULL)
    fprintf(ERR_STRM,"name     = %s\t", ctx->member_name);
  else fprintf(ERR_STRM,"name     = NULL\t");
  if(ctx->group_name != NULL)
    fprintf(ERR_STRM,"group    = %s\t", ctx->group_name);
  else fprintf(ERR_STRM,"group    = NULL\t");
  if(ctx->group_secret != NULL){
    fprintf(ERR_STRM,"grpsecret= ");
	nn_print("grpsecret= ", ctx->group_secret);
    fprintf(ERR_STRM,"\n");
  }
  else fprintf(ERR_STRM,"grpsecret= NULL\n");
  if(ctx->epoch != (int)NULL){
    fprintf(ERR_STRM,"epoch= %d\n", ctx->epoch);
  }
  else fprintf(ERR_STRM,"epoch= NULL\n");

  tgdh_print_all(name, ctx->root);

  return;
}

void tgdh_simple_ctx_print(TGDH_CONTEXT *ctx){
  if(ctx == NULL) fprintf(ERR_STRM, "\n\nTREE is NULL\n");
  else{
    fprintf(stderr, "\n\n========TREE for member %s ========\n",
            ctx->member_name);  
    tgdh_simple_node_print(ctx->root);
  }
}

void tgdh_simple_node_print(KEY_TREE *tree){
  KEY_TREE *tmp_tree=NULL;
    int power2[16]={0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100,
                    0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000};

  int i=0, k=0;

  /*
    for(i=2; i<(int)pow(2, tree->tgdh_nv->height+2); i += 2){
    for(j=0; j<8; j++){
    if(i == power2[j]) {
    fprintf(stderr, "\n");
    for(k=0; k<(int)(pow(2, tree->tgdh_nv->height+2)/i) - 2; k++)
    fprintf(stderr, " ");
    }
    }
    
    tmp_tree = tgdh_search_index(tree, i);
    if(tmp_tree == NULL) fprintf(ERR_STRM,"   ");
    else{
    if(tmp_tree->tgdh_nv->key != NULL) fprintf(ERR_STRM, "+ ");
    else fprintf(ERR_STRM, "- ");
    if(tmp_tree->tgdh_nv->bkey != NULL) fprintf(ERR_STRM, "+");
    else fprintf(ERR_STRM, "-");
    }
    for(k=0; k<(int)(pow(2, tree->tgdh_nv->height+3 - 
    (int)(log(i)/log(2)))) - 3; k++)
    fprintf(stderr, " ");
    }
  */
                              
  for(i=1; i<(int)pow(2, tree->tgdh_nv->height); i++){
    if(log(i)/log(2) - clq_log2(i) < 0.0001) {
      fprintf(stderr, "\n");
      for(k=0; k<power2[tree->tgdh_nv->height-clq_log2(i)-1]-1; k++)
        fprintf(stderr, " ");
    }
    else{
      for(k=0; k<power2[tree->tgdh_nv->height-clq_log2(i-1)]-1; k++)
        fprintf(stderr, " ");
    }

    tmp_tree = tgdh_search_number(tree, i);
    if(i==1) fprintf(ERR_STRM,"1");
    else if(tmp_tree == NULL) fprintf(ERR_STRM," ");
    else if(tmp_tree->tgdh_nv->index) fprintf(ERR_STRM,"%d",tmp_tree->tgdh_nv->index);
    else fprintf(ERR_STRM," ");
    
  }
  
}

/* tgdh_search_number: Returns the node having the index
 */
KEY_TREE *tgdh_search_number(KEY_TREE *tree, int index)
{
  int height=0;
  int i;
  KEY_TREE *tmp_tree;
  
  height = clq_log2(index);
  
  tmp_tree = tree;
  
  for(i=1; i<=height; i++){
    if((index >> (height-i)) & 0x1){
      if(tmp_tree->right == NULL) return NULL;
      else tmp_tree = tmp_tree->right;
    }
    else{
      if(tmp_tree->left == NULL) return NULL;
      else tmp_tree = tmp_tree->left;
    }
  }
  
  return tmp_tree;
}

void tgdh_print_node(char *name, KEY_TREE *tree) {
  /*  fprintf(ERR_STRM,"\n\t---tree print %s ---\n\t", name);*/
  if(tree->tgdh_nv != NULL){
    fprintf(ERR_STRM,"index     = %d\t", tree->tgdh_nv->index);
    if(tree->tgdh_nv->joinQ == TRUE)
      fprintf(ERR_STRM,"joinQ     = %d\t", tree->tgdh_nv->joinQ);
    else fprintf(ERR_STRM,"joinQ     = FALSE\t");
    if(tree->tgdh_nv->potential > -2) 
      fprintf(ERR_STRM,"potential = %d\t", tree->tgdh_nv->potential);
    else fprintf(ERR_STRM,"potential = NULL\t");
    if(tree->tgdh_nv->height > -2)
      fprintf(ERR_STRM,"height    = %d\t", tree->tgdh_nv->height);
    else fprintf(ERR_STRM,"height    = NULL\t");
    if(tree->tgdh_nv->num_node > -2)
      fprintf(ERR_STRM,"num_node  = %d\n\t", tree->tgdh_nv->num_node);
    else fprintf(ERR_STRM,"num_node  = NULL\n\t");
    if(tree->tgdh_nv->key != NULL){
	  priv_key_print("key  = ", tree->tgdh_nv->key);
    }
    else fprintf(ERR_STRM,"key  = NULL");
    if(tree->tgdh_nv->bkey != NULL){
      //fprintf(ERR_STRM,"\n\tbkey = ");
	  pub_key_print("\n\tbkey = ", tree->tgdh_nv->bkey);
    }
    else fprintf(ERR_STRM,"\n\tbkey = NULL");
    fprintf(ERR_STRM,"\n\tmypt      = %x\t", (int)tree);
    if(tree->tgdh_nv->member != NULL){
      if(tree->tgdh_nv->member->member_name != NULL)
        fprintf(ERR_STRM,"name      = %s\n\t", tree->tgdh_nv->member->member_name);
      else fprintf(ERR_STRM, "name     = NULL\n\t");  
      if(tree->tgdh_nv->member->cert != NULL)
        fprintf(ERR_STRM,"cert      = %x\n\t", (int)tree->tgdh_nv->member->cert);
      else fprintf(ERR_STRM, "cert     = NULL\n\t");  
    }
    if(tree->parent != NULL)
      fprintf(ERR_STRM,"prntpt    = %x\t", (int)tree->parent);
    if(tree->left != NULL)
      fprintf(ERR_STRM,"leftpt    = %x\t", (int)tree->left);
    if(tree->right != NULL)
      fprintf(ERR_STRM,"rightpt   = %x\t", (int)tree->right);
    if(tree->prev != NULL)
      fprintf(ERR_STRM,"prevpt    = %x\t", (int)tree->prev);
    if(tree->next != NULL)
      fprintf(ERR_STRM,"nextpt    = %x\t", (int)tree->next);
  }
  
  return;
}

void tgdh_print_all(CLQ_NAME *name, KEY_TREE *tree) {
  if(tree == NULL) return;
  tgdh_print_node(name,tree);
  tgdh_print_all(name, tree->left);
  tgdh_print_all(name, tree->right);
}

void tgdh_print_simple(CLQ_NAME *name, KEY_TREE *tree) {
  if(tree == NULL) return;
  tgdh_print_bkey(name,tree);
  tgdh_print_simple(name, tree->left);
  tgdh_print_simple(name, tree->right);
}

void tgdh_print_bkey(char *name, KEY_TREE *tree) {
  fprintf(ERR_STRM,"%s ", name);
  if(tree->tgdh_nv != NULL){
    fprintf(ERR_STRM,"ind = %02d ", tree->tgdh_nv->index);
    if(tree->tgdh_nv->member != NULL){
      if(tree->tgdh_nv->member->member_name != NULL)
        fprintf(ERR_STRM,"name = %s ", tree->tgdh_nv->member->member_name);
      else fprintf(ERR_STRM, "name = NUL ");  
    }
    else fprintf(ERR_STRM, "name = NUL ");  
    if(tree->tgdh_nv->bkey != NULL){
      fprintf(ERR_STRM,"\n\tbkey =");
      BN_print_fp(ERR_STRM, tree->tgdh_nv->bkey);
    }
    else fprintf(ERR_STRM,"\n\tbkey = NUL       ");
    if(tree->tgdh_nv->key != NULL){
      fprintf(ERR_STRM,"\n\tkey  =");
      BN_print_fp(ERR_STRM, tree->tgdh_nv->key);
    }
    else fprintf(ERR_STRM,"\n\tkey  = NUL");
    fprintf(ERR_STRM,"\n");
  }
  
  return;
}

int compare_key(TGDH_CONTEXT *ctx[], int num) {
  int i=0;
  nn *tmp_key=NULL;

  for(i=0; i<num; i++)
    if(ctx[i])
      if(ctx[i]->root->tgdh_nv->key)
        tmp_key=ctx[i]->root->tgdh_nv->key;
    
  for(i=0; i<num; i++){
    if(ctx[i] != NULL){
      if(nn_cmp(tmp_key, ctx[i]->root->tgdh_nv->key) != 0){
        fprintf(stderr, "()()())(()()()()()()()()()\n");
        return -1;
      }
    }
    else{
      printf("***************Some context is empty\n");
    }
  }
  
#ifdef DEBUG_ALL    
  fprintf(stderr, "\n\n\nAll right... All keys are same!!!\n");
  fprintf(stderr, "All right... All keys are same!!!\n");
  fprintf(stderr, "All right... All keys are same!!!\n");
#endif
  
  return 1;
}

/* tgdh_get_secret: Returns in a static variable with
 * ctx->group_secret_hash 
 */ 
clq_uchar *tgdh_get_secret(TGDH_CONTEXT *ctx) {
  static clq_uchar tmp[MD5_DIGEST_LENGTH];

  memcpy (tmp,ctx->group_secret_hash,MD5_DIGEST_LENGTH);

  return tmp;
}

void tgdh_print_group_secret(TGDH_CONTEXT *ctx) {
  int i;

  fprintf(ERR_STRM,"Group Secret (MD5): ");
  if (ctx->group_secret_hash == NULL) fprintf (ERR_STRM,"EMPTY");
  else {
    for (i=0; i < MD5_DIGEST_LENGTH; i++) 
      fprintf(ERR_STRM, "%02X",ctx->group_secret_hash[i]);
  }

  fprintf(ERR_STRM,"\n");
}
