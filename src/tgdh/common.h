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
 * common.h                                                          * 
 * Common header file         .                                      * 
 * Date      Mon Jun 17, 2002 11:24 AM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/
#ifndef CLQ_CERT_H
#define CLQ_CERT_H
//#include "openssl/bio.h"
//#include "openssl/err.h"
//#include "openssl/dsa.h"
//#include "openssl/x509.h"
#include "../openssl/x509.h"
#include "../nn/nn.h"//ccw+
#include "../sig/ecdsa.h"
#include "../sig/ec_key.h"
//#include "asn1.h"

/* data structures */
typedef char CLQ_NAME;
#ifndef clq_uchar
typedef unsigned char clq_uchar;
#endif
#ifndef clq_uint
typedef unsigned int clq_uint;
#endif

#define ERR_STRM stderr /* If DEBUG is enable then extra information
			 * will be printed in ERR_STRM 
			 */
/***************************************************************/
/* Be careful... previously, 32768                             */
/* I changed since for 148 users, we need more than 32768 bytes*/
/***************************************************************/
#define MSG_SIZE 65536
#define INT_SIZE sizeof(int)
#define LENGTH_SIZE 4 /* The length of the size in a token */
#define TOTAL_INT INT_SIZE+LENGTH_SIZE
#define MAX_LIST 200 /* Maximum number of members */ 
typedef struct stack_st {
    int num;
    char **data;
    int sorted;
    int num_alloc;
    int (*comp) (const void *, const void *);
} _STACK;
#define STACK_OF(type) struct stack_st_##type
# define PREDECLARE_STACK_OF(type) STACK_OF(type);

# define DECLARE_STACK_OF(type) \
STACK_OF(type) \
    { \
    _STACK stack; \
    };
# define DECLARE_SPECIAL_STACK_OF(type, type2) \
STACK_OF(type) \
    { \
    _STACK stack; \
    };

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

/* clq_get_cert stuff */
#define DSA_PARAM_CERT "dsa_param.pem"
#define PUB_CERT "cert"
#define CA_CERT_FN "cacert.pem"

#define MAX_LGT_NAME 50 /* Maximum length a CLQ_NAME can have. */

/* clq_read_DSA stuff */
#define COMMON_FILE "public_values.clq"
#define PUB_FMT "pub"
#define PRV_FMT "priv"
#ifdef USE_CLQ_READ_DSA
#define FILE_EXT "clq"
#else
#define FILE_EXT "pem"
#endif

/* clq_get_cert stuff */
#define DSA_PARAM_CERT "dsa_param.pem"
#define PUB_CERT "cert"
#define CA_CERT_FN "cacert.pem"

/* Macros not implemented in SSL */
#ifndef d2i_DSAPublicKey_bio
#define d2i_DSAPublicKey_bio(bp,x) (DSA *)ASN1_d2i_bio((char *(*)())DSA_new, \
                (char *(*)())d2i_DSAPublicKey,(bp),(unsigned char **)(x))
#endif
#ifndef i2d_DSAPublicKey_bio
#define i2d_DSAPublicKey_bio(bp,x) ASN1_i2d_bio(i2d_DSAPublicKey,(bp), \
                (unsigned char *)(x)) 
#endif

/* Private Macros */

#ifndef MAX
#define MAX(x,y)                        ((x)>(y)?(x):(y))
#endif
#ifndef MIN
#define MIN(x,y)                        ((x)<(y)?(x):(y))
#endif

/* CLQ_KEY_TYPE definitions, used by clq_read_dsa */
enum CLQ_KEY_TYPE { CLQ_PARAMS,
                    CLQ_PRV,
                    CLQ_PUB};

typedef struct clq_token_st {
  unsigned int length;//uint length;
  clq_uchar *t_data;
} CLQ_TOKEN;
//ccw+s
#define BN_ULONG        unsigned int
#define SHA_DIGEST_LENGTH 20
typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;

#ifdef NO_ASN1_TYPEDEFS
#define ASN1_INTEGER            ASN1_STRING
#define ASN1_ENUMERATED         ASN1_STRING
#define ASN1_BIT_STRING         ASN1_STRING
#define ASN1_OCTET_STRING       ASN1_STRING
#define ASN1_PRINTABLESTRING    ASN1_STRING
#define ASN1_T61STRING          ASN1_STRING
#define ASN1_IA5STRING          ASN1_STRING
#define ASN1_UTCTIME            ASN1_STRING
#define ASN1_GENERALIZEDTIME    ASN1_STRING
#define ASN1_TIME               ASN1_STRING
#define ASN1_GENERALSTRING      ASN1_STRING
#define ASN1_UNIVERSALSTRING    ASN1_STRING
#define ASN1_BMPSTRING          ASN1_STRING
#define ASN1_VISIBLESTRING      ASN1_STRING
#define ASN1_UTF8STRING         ASN1_STRING
#define ASN1_BOOLEAN            int
#define ASN1_NULL               int
#else
typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_string_st ASN1_ENUMERATED;
typedef struct asn1_string_st ASN1_BIT_STRING;
typedef struct asn1_string_st ASN1_OCTET_STRING;
typedef struct asn1_string_st ASN1_PRINTABLESTRING;
typedef struct asn1_string_st ASN1_T61STRING;
typedef struct asn1_string_st ASN1_IA5STRING;
typedef struct asn1_string_st ASN1_GENERALSTRING;
typedef struct asn1_string_st ASN1_UNIVERSALSTRING;
typedef struct asn1_string_st ASN1_BMPSTRING;
typedef struct asn1_string_st ASN1_UTCTIME;
typedef struct asn1_string_st ASN1_TIME;
typedef struct asn1_string_st ASN1_GENERALIZEDTIME;
typedef struct asn1_string_st ASN1_VISIBLESTRING;
typedef struct asn1_string_st ASN1_UTF8STRING;
typedef struct asn1_string_st ASN1_STRING;
typedef int ASN1_BOOLEAN;
typedef int ASN1_NULL;
#endif




typedef struct ecdsa_verify_data dsa_st;
typedef struct ec_pub_key NN_PKEY;
typedef struct dsa_st DSA;
//
typedef struct x509_st X509;
//
//ccw+e
#ifdef TIMING
double clq_gettimeofday(void);
#endif

DSA *clq_get_dsa_key (char *member_name, 
                      enum CLQ_KEY_TYPE type);

struct EVP_PKEY *clq_get_pkey (char *member_name);

DSA *clq_get_dsa_param();

X509 *clq_get_cert (char *member_name);

X509 *clq_vrfy_cert(X509_STORE *ctx, char *file);

/* clq_read_DSA: Reads a DSA structure from disk depending on
 * CLQ_KEY_TYPE (CLQ_PARAMS, CLQ_PRIV, CLQ_PUB)
 * Returns the structure if succeed otherwise NULL is returned.
 */
DSA *clq_read_dsa(char *member_name, enum CLQ_KEY_TYPE type);

/* max: return maximum of a and b */
int max(int a, int b);
/* return log_2 a */
int clq_log2(int a);
/* swap pointer a and b */
void clq_swap(void **a, void **b);

/* int_endoce: It puts an integer number in stream. Note that the size
 * of the integer number is addded to the stream as well.
 */
/* NOTE: HTONL should be added here */
void int_encode(clq_uchar *stream, clq_uint *pos, clq_uint data);


/* int_decode: It gets an integer number from input->t_data. Note that
 * the size of the integer number is decoded first, and then the
 * actual number is decoded.
 * Returns: 1 succeed.
 *          0 Fails.
 */
int int_decode(const CLQ_TOKEN *input,clq_uint *pos, clq_uint *data);

/* string_encode: It puts the valid 'c' string into stream. It first
 * stores the message length (including \0) and the the actual
 * message.
 */
void string_encode (clq_uchar *stream, clq_uint *pos, char *data);

/* string_decode: It restores a valid 'c' string from
 * input->t_data. First the string length is decode (this one should
 * have \0 already), and the actual string.
 * Returns: 1 succeed.
 *          0 Fails.
 */
int string_decode (const CLQ_TOKEN *input, clq_uint *pos, char *data);

/* bn_encode: BIGNUM encoding. */
void bn_encode (clq_uchar *stream, clq_uint *pos, nn *num);

/* bn_decode: BIGNUM decoding.
 * Preconditions: num has to be different from NULL.
 * Returns: 1 succeed.
 *          0 Fails.
 */
int bn_decode (const CLQ_TOKEN *input, clq_uint *pos, nn *num);

#endif
