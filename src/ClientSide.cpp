/************************************************************************
 * envirnment: ubuntu codeblcoks
 *
 * Author: xchan - Xiang chuan
 *
 * Email:koolerxc@gmail.com
 *
 ************************************************************************/
#include "ClientSide.h"

ClientSide::ClientSide()
{
    //ctor

    //salt len 20
    //get the random value

    m_rand_a = BN_new();
    unsigned char *tmp;
    if (m_rand_a != NULL && (tmp = (unsigned char *)malloc(2500*sizeof(char))) !=NULL)
    {
        RAND_pseudo_bytes(tmp, 20);
        m_rand_a = BN_bin2bn(tmp, 20, NULL);
        free(tmp);
//        print_bn(m_rand_b);
    }
    //get the default g and n
    m_base_g = &bn_generator_2;
    m_base_N = &bn_group_1024;
//    print_bn(m_base_g);
//    print_bn(m_base_N);
}

ClientSide::~ClientSide()
{
    //dtor
}

BIGNUM *ClientSide::Calc_k(BIGNUM *g,BIGNUM *N)
{
    /* k = SHA1(N | PAD(g)) -- tls-srp draft 8 */
    unsigned char digest[SHA_DIGEST_LENGTH];
    unsigned char *tmp;
    EVP_MD_CTX ctxt;
    int longg;
    int longN = BN_num_bytes(N);
    if (BN_ucmp(g, N) >= 0)
        return NULL;
    if ((tmp =(unsigned char*) OPENSSL_malloc(longN)) == NULL)
        return NULL;
    BN_bn2bin(N, tmp);
    EVP_MD_CTX_init(&ctxt);
    EVP_DigestInit_ex(&ctxt, EVP_sha1(), NULL);
    EVP_DigestUpdate(&ctxt, tmp, longN);

    memset(tmp, 0, longN);
    longg = BN_bn2bin(g, tmp);
    /* use the zeros behind to pad on left */
    EVP_DigestUpdate(&ctxt, tmp + longg, longN - longg);
    EVP_DigestUpdate(&ctxt, tmp, longg);
    OPENSSL_free(tmp);

    EVP_DigestFinal_ex(&ctxt, digest, NULL);
    EVP_MD_CTX_cleanup(&ctxt);
    return BN_bin2bn(digest, sizeof(digest), NULL);

}


BIGNUM *ClientSide::Calc_A(BIGNUM *g,BIGNUM* a,BIGNUM *N)
{
    //BN_mod_exp paramater
    BN_CTX *bn_ctx;
    bn_ctx = BN_CTX_new();

    //init A
    BIGNUM *A = NULL;
    A = BN_new();

// TODO (xchan#1#):  all calculate is under mod N!!!!
    if (!BN_mod_exp(A, g, a, N, bn_ctx))
    {
        BN_free(A);
        A = NULL;
    }
    BN_CTX_free(bn_ctx);
    return A;
}

BIGNUM *ClientSide::Calc_u(BIGNUM *A,BIGNUM *B,BIGNUM *N)
{


    BIGNUM *u;
    //SHA_DIGEST_LENGTH =20
    unsigned char cu[SHA_DIGEST_LENGTH];
    unsigned char *cAB;
    EVP_MD_CTX ctxt;
    int longN;
    if ((A == NULL) || (B == NULL) || (N == NULL))
        return NULL;
// TODO (xchan#1#):  ...
//why compare?
//i think A and B all  are smaller than base N; so if A or B bigger ,this number is wrong

    if (BN_ucmp(A, N) >= 0 || BN_ucmp(B, N) >= 0)
        return NULL;
    longN = BN_num_bytes(N);
    if ((cAB =(unsigned char*) OPENSSL_malloc(2 * longN)) == NULL)
        return NULL;
    memset(cAB, 0, longN);
    EVP_MD_CTX_init(&ctxt);
    EVP_DigestInit_ex(&ctxt, EVP_sha1(), NULL);
    // TODO (xchan#1#): PAD(n) means  add at the last, padding
    EVP_DigestUpdate(&ctxt, cAB + BN_bn2bin(A, cAB + longN), longN);
    EVP_DigestUpdate(&ctxt, cAB + BN_bn2bin(B, cAB + longN), longN);
    OPENSSL_free(cAB);
    EVP_DigestFinal_ex(&ctxt, cu, NULL);
    EVP_MD_CTX_cleanup(&ctxt);
    if (!(u = BN_bin2bn(cu, sizeof(cu), NULL)))
        return NULL;
    if (!BN_is_zero(u))
        return u;
    BN_free(u);
    return NULL;
}
BIGNUM *ClientSide::Calc_x(BIGNUM *s,const char * uname,const char *p)
{
// TODO (xchan#1#): x = SHA1(s | SHA1(username | ":" | P))
// s is salt

    unsigned char dig[SHA_DIGEST_LENGTH];
    EVP_MD_CTX ctxt;
    unsigned char *cs;
    if ((s == NULL) || (uname == NULL) || (p == NULL))
        return NULL;
    if ((cs = (unsigned char *)OPENSSL_malloc(BN_num_bytes(s))) == NULL)
        return NULL;
    EVP_MD_CTX_init(&ctxt);
    EVP_DigestInit_ex(&ctxt, EVP_sha1(), NULL);
    EVP_DigestUpdate(&ctxt, uname, strlen(uname));
    EVP_DigestUpdate(&ctxt, ":", 1);
    EVP_DigestUpdate(&ctxt, p, strlen(p));
    EVP_DigestFinal_ex(&ctxt, dig, NULL);
    EVP_DigestInit_ex(&ctxt, EVP_sha1(), NULL);
    BN_bn2bin(s, cs);
    EVP_DigestUpdate(&ctxt, cs, BN_num_bytes(s));
    OPENSSL_free(cs);
    EVP_DigestUpdate(&ctxt, dig, sizeof(dig));
    EVP_DigestFinal_ex(&ctxt, dig, NULL);
    EVP_MD_CTX_cleanup(&ctxt);
    return BN_bin2bn(dig, sizeof(dig), NULL);

}
BIGNUM *ClientSide::Calc_S(BIGNUM *B,BIGNUM *k,BIGNUM *g,BIGNUM *a,BIGNUM *u,BIGNUM *x,BIGNUM *N)
{
//S = (B - kg^x) ^ (a + ux)   (computes session key)
    BIGNUM *tmp = NULL, *tmp2 = NULL, *tmp3 = NULL, *S = NULL;
    BN_CTX *bn_ctx;
    if (u == NULL || B == NULL || N == NULL || g == NULL || x == NULL
            || a == NULL || (bn_ctx = BN_CTX_new()) == NULL || k == NULL)
        return NULL;
    if ((tmp = BN_new()) == NULL ||
            (tmp2 = BN_new()) == NULL ||
            (tmp3 = BN_new()) == NULL || (S = BN_new()) == NULL)
    {
        BN_CTX_free(bn_ctx);
        BN_clear_free(tmp);
        BN_clear_free(tmp2);
        BN_clear_free(tmp3);
        BN_free(S);
        return NULL;
    }
    if(BN_mod_exp(tmp, g, x, N, bn_ctx))
        if(BN_mod_mul(tmp2, tmp, k, N, bn_ctx))
            if(BN_mod_sub(tmp, B, tmp2, N, bn_ctx))
                if(BN_mod_mul(tmp3, u, x, N, bn_ctx))
                    if(BN_mod_add(tmp2, a, tmp3, N, bn_ctx))
                        if(BN_mod_exp(S, tmp, tmp2, N, bn_ctx))
                            ;
    BN_CTX_free(bn_ctx);
    BN_clear_free(tmp);
    BN_clear_free(tmp2);
    BN_clear_free(tmp3);
    return S;

}

BIGNUM* ClientSide::Calc_HashKey(BIGNUM *S)
{
    unsigned char dig[SHA_DIGEST_LENGTH];
    EVP_MD_CTX ctxt;
    unsigned char *cs;
    if (S == NULL)
        return NULL;
    if ((cs = (unsigned char *)OPENSSL_malloc(BN_num_bytes(S))) == NULL)
        return NULL;
    EVP_MD_CTX_init(&ctxt);
    EVP_DigestInit_ex(&ctxt, EVP_sha1(), NULL);
    BN_bn2bin(S, cs);
    EVP_DigestUpdate(&ctxt, cs, BN_num_bytes(S));
    OPENSSL_free(cs);
    EVP_DigestFinal_ex(&ctxt, dig, NULL);
    EVP_MD_CTX_cleanup(&ctxt);
    return BN_bin2bn(dig, sizeof(dig), NULL);
}




BIGNUM *ClientSide::makeHash(BIGNUM *data1,BIGNUM *data2,const char* hashName)
{
    //byte stream translation, so use bytes not the bits
    int len_of_data1 = BN_num_bytes(data1);
    //translate from the bignum to char * to make hash
    unsigned char *tmp;
    //tmp = malloc(m_base_N*sizeof(char *));
    BN_bn2bin(data1, tmp);

    EVP_MD_CTX mdctx;
    const EVP_MD *hash;

    unsigned char md_value[200];
    unsigned int md_len;
    int i;
    OpenSSL_add_all_digests();

    hash = EVP_get_digestbyname(hashName);

    //init digets
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, hash, NULL);

    //hash data 1
    EVP_DigestUpdate(&mdctx, data1, len_of_data1);

    //hash data2

    //digest output
    EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
    EVP_MD_CTX_cleanup(&mdctx);

    return BN_bin2bn(md_value,md_len,NULL);
}

void ClientSide::set_username(const char *uname)
{
    this->username = uname;

}
void ClientSide::set_password(const char *pd)
{
    this->password = pd;
}




