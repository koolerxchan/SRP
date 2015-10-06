/************************************************************************
 * envirnment: ubuntu codeblcoks
 *
 * Author: xchan - Xiang chuan
 *
 * Email:koolerxc@gmail.com
 *
 ************************************************************************/
#include "ServerSide.h"
using namespace std;

ServerSide::ServerSide()
{
    //salt len 20
    //get the random value
    m_rand_b = BN_new();
    unsigned char *tmp;
    if (m_rand_b != NULL && (tmp = (unsigned char *)malloc(2500*sizeof(char))) !=NULL)
    {
        RAND_pseudo_bytes(tmp, 20);
        m_rand_b = BN_bin2bn(tmp, 20, NULL);
        free(tmp);
        //print_bn(m_rand_b);
    }

    m_rand_s = BN_new();
    if (m_rand_s != NULL && (tmp = (unsigned char *)malloc(2500*sizeof(char))) !=NULL)
    {
        RAND_pseudo_bytes(tmp, 20);
        m_rand_s = BN_bin2bn(tmp, 20, NULL);
        free(tmp);
        //print_bn(m_rand_s);
    }


    //get the default g and n
    m_base_g = &bn_generator_2;
    m_base_N = &bn_group_1024;
    // print_bn(m_base_g);
    // print_bn(m_base_N);

}

ServerSide::~ServerSide()
{
    //dtor
}


BIGNUM *ServerSide::Calc_k(BIGNUM *g,BIGNUM *N)
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

BIGNUM *ServerSide::Calc_x(BIGNUM *s,const char * uname,const char *p)
{
// TODO (xchan#1#): x = SHA1(s | SHA1(username | ":" | P))
// s is salt
    unsigned char dig[SHA_DIGEST_LENGTH];
    EVP_MD_CTX ctxt;
    unsigned char *cs;
    if ((s == NULL) || (uname == NULL) || (p == NULL))
    {
        cout<<"test"<<endl;
        return NULL;
    }
    if ((cs = (unsigned char *)OPENSSL_malloc(BN_num_bytes(s))) == NULL)
    {
        cout<<"test1"<<endl;
        return NULL;
    }
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

BIGNUM *ServerSide::Calc_B(BIGNUM *k,BIGNUM *v,BIGNUM *g,BIGNUM *b,BIGNUM *N)
{
    //B = kv + g^b
    bool flag = false;
    if((k == NULL) || (v == NULL) || (g == NULL) || (N == NULL))
    {
        cout<<"if null"<<endl;
        return NULL;
    }
    BIGNUM *tmp = NULL, *tmp1 = NULL, *tmp2 = NULL;
    BN_CTX *bn_ctx;
    if((tmp = BN_new()) == NULL || (tmp1 = BN_new()) == NULL
            || (bn_ctx = BN_CTX_new())==NULL || (tmp2 = BN_new()) == NULL)
    {
        BN_clear_free(tmp);
        BN_clear_free(tmp1);
        BN_clear_free(tmp2);
        BN_CTX_free(bn_ctx);
        return NULL;
    }
//    cout<<"test"<<endl;
//    print_bn(g);
//    print_bn(b);
//    print_bn(N);
    if(BN_mod_exp(tmp,g,b,N,bn_ctx))
        if(BN_mod_mul(tmp1,k,v,N,bn_ctx))
            if(BN_mod_add(tmp2,tmp,tmp1,N,bn_ctx));
    {
        //if all excute successful
        flag = true;
    }
    BN_CTX_free(bn_ctx);
    BN_clear_free(tmp);
    BN_clear_free(tmp1);
    if(flag)
        return tmp2;
    else
        return NULL;
}


BIGNUM *ServerSide::Calc_u(BIGNUM *A,BIGNUM *B,BIGNUM *N)
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


BIGNUM *ServerSide::Calc_v(BIGNUM *g,BIGNUM *x,BIGNUM *N)
{
    //v = g^x
    BIGNUM *v = NULL;
    BN_CTX *bn_ctx;
    if ((g == NULL) || (x == NULL) || (N == NULL))
        return NULL;
    if((v = BN_new()) == NULL || (bn_ctx = BN_CTX_new())== NULL)
    {
        BN_clear_free(v);
        BN_CTX_free(bn_ctx);
        return v;
    }
    if(BN_mod_exp(v,g,x,N,bn_ctx))
    {
        BN_CTX_free(bn_ctx);

        //print_bn(v);
        return v;
    }

    BN_CTX_free(bn_ctx);
    return NULL;
}

BIGNUM *ServerSide::Calc_SessionKey(BIGNUM *A,BIGNUM *v,BIGNUM *u,BIGNUM *b,BIGNUM *N)
{
    ////S = (Av^u) ^ b
    bool excute_flag = false;
    BIGNUM *tmp = NULL, *tmp1 = NULL, *S = NULL;
    BN_CTX *bn_ctx = NULL;
    if(A == NULL || v == NULL || b == NULL || N == NULL
            || (tmp = BN_new()) == NULL || (tmp1 = BN_new()) == NULL
            || (S = BN_new()) == NULL || (bn_ctx = BN_CTX_new()) == NULL)
    {
        BN_clear_free(tmp);
        BN_clear_free(tmp1);
        BN_clear_free(S);
        BN_CTX_free(bn_ctx);
        return NULL;
    }
    if(BN_mod_exp(tmp,v,u,N,bn_ctx))
        if(BN_mod_mul(tmp1,A,tmp,N,bn_ctx))
            if(BN_mod_exp(S,tmp1,b,N,bn_ctx))
            {
                excute_flag =true;
            }
    BN_clear_free(tmp);
    BN_clear_free(tmp1);

    BN_CTX_free(bn_ctx);
    if(excute_flag)
        return S;
    BN_clear_free(S);
    return NULL;
}

BIGNUM* ServerSide::Calc_HashKey(BIGNUM *S)
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


void ServerSide::set_username(const char *uname)
{
    this->username = uname;

}
void ServerSide::set_password(const char *pd)
{
    this->password = pd;
}




























