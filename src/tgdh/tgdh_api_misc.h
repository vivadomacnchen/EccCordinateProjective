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
 * tgdh_api_misc.h                                                   * 
 * TREE api miscellaneous include file.                              * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#ifndef TGDH_API_MISC_H
#define TGDH_API_MISC_H

#include <stdio.h>

#include "openssl/dsa.h"
#include "tgdh_api.h"

#define FN_LENGTH 200
#define Q_SIZE_IN_BITS 160

int tgdh_print_dsa(DSA *dsa);

KEY_TREE *tgdh_search_number(KEY_TREE *tree, int index);

void tgdh_print_node(char *name, KEY_TREE *tree);
void tgdh_print_all(CLQ_NAME *name, KEY_TREE *tree);
void tgdh_print_ctx(char *name, TGDH_CONTEXT *ctx);
void tgdh_simple_ctx_print(TGDH_CONTEXT *ctx);
void tgdh_simple_node_print(KEY_TREE *tree);
void tgdh_print_bkey(char *name, KEY_TREE *tree);
void tgdh_print_simple(CLQ_NAME *name, KEY_TREE *tree);

int compare_key(TGDH_CONTEXT *ctx[], int num);

/* tgdh_get_secret: Returns in a static variable with ctx->group_secret_hash */
clq_uchar *tgdh_get_secret(TGDH_CONTEXT *ctx);

void tgdh_print_group_secret(TGDH_CONTEXT *ctx);

#endif
