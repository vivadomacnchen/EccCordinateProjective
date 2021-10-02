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
 * tgdh_sig.h                                                         * 
 * TREE signature include file.                                       * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#ifndef TGDH_SIG_H
#define TGDH_SIG_H

//#include "openssl/evp.h"
//#include "openssl/x509.h"

#include "tgdh_api.h"

/* Both md below use sha1 */
#define RSA_MD() EVP_sha1() /* NID_sha1WithRSAEncryption see m_sha1.c */
#define DSA_MD() EVP_dss1() /* NID_dsaWithSHA1 see m_dss1.c */

typedef struct tgdh_sign_st {
  clq_uchar *signature;
  unsigned int length;
} TGDH_SIGN;


/* tgdh_sign_message: It signs the token using the current user public
 * key scheme. The signature will be appended to the begining of the
 * input token
 */
int tgdh_sign_message(TGDH_CONTEXT *ctx, CLQ_TOKEN *input, ec_key_pair key_pair, const char *hdr_type, const char *version);

int tgdh_vrfy_sign(const char *ec_name, const char *ec_sig_name, const char *hash_algorithm, TGDH_CONTEXT *ctx, TGDH_CONTEXT *new_ctx,
		   CLQ_TOKEN *input,  CLQ_NAME *member_name,
		   TGDH_SIGN *sign);

int tgdh_remove_sign(CLQ_TOKEN *input, TGDH_SIGN **sign);
int tgdh_restore_sign(CLQ_TOKEN *input, TGDH_SIGN **signature);

#endif
