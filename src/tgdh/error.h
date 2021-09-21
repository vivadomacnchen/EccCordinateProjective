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
 * error.h                                                           * 
 * error codes for cliques library                                   * 
 * Wrote by:                                                         * 
 *  Yongdae Kim                                                      *
 *                                                                   *
 * CLIQUES Project                                                   *
 * Information and Computer Science                                  *
 * University of California at Irvine                                *
 *********************************************************************/
#ifndef CLQ_ERROR_H
#define CLQ_ERROR_H

/* Return codes */
#define OK                          1
#define CONTINUE                    2
#define KEY_COMPUTED                3

/* General errors */
#define CTX_ERROR                  -1
#define INVALID_INPUT_TOKEN       -10
#define INVALID_MESSAGE_TYPE      -11
#define INVALID_MEMBER_NAME       -12
#define INVALID_GROUP_NAME        -13
#define GROUP_NAME_MISMATCH       -14
#define INVALID_LGT_NAME          -15
#define MEMBER_IS_IN_GROUP        -16
#define MEMBER_NOT_IN_GROUP       -17
#define MEMBER_NAME_MISMATCH      -18
#define MEMBER_REPEATED           -19
#define LIST_EMPTY                -20
#define STRUCTURE_ERROR           -21
#define MERGE_FAILURE             -22
#define NOT_CONTROLLER            -23
#define UNSYNC_EPOCH              -24
#define SEVERAL_JOINS             -25
#define SENDER_NOT_CONTROLLER     -26
#define MALLOC_ERROR              -27
#define BN_ERROR                  -28
#define ERROR_INT_DECODE          -29
#define GML_EMPTY                 -30
#define ONE_RCVD                  -31
#define ZERO_RCVD                 -32
#define NUM_NOT_IN_GROUP          -33
#define MOD_INVERSE_ERROR         -34
#define MOD_MUL_ERROR             -35
#define MOD_EXP_ERROR             -36
#define BN_CONVERT_ERROR          -37

/* Certificate Related */
#define INVALID_DSA_PARAMS        -40
#define INVALID_PUB_KEY           -41
#define INVALID_PRIV_KEY          -42
#define INVALID_PARAM             -43
#define INVALID_DSA_TYPE          -44 
#define INVALID_CA_FILE           -45
#define INVALID_CERT_FILE         -46
#define INVALID_PKEY              -47


/* Signature Related */
#define INVALID_SIGNATURE_SCHEME  -50
#define SIGNATURE_ERROR           -51
#define SIGNATURE_DIFER           -52
#define INVALID_SIGNATURE         -53

#endif
