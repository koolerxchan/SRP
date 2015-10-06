#ifndef CLIENTSIDE_H
#define CLIENTSIDE_H
/* openssl big number caculate library*/
#include <openssl/bn.h>
#include <dlfcn.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <cstring>
#include <openssl/rand.h>
#include <NUM_gn.h>
#include<string>
#include<iostream>
#define print_bn(a) {fprintf(stderr, #a " = ");BN_print_fp(stderr,a);fprintf(stderr,"\n");}


using namespace std;
class ClientSide
{
public:
    ClientSide();
    virtual ~ClientSide();
// TODO (xchan#1#): in tls-draft , u's defination is more accurate,
//                  so must read orignal draft to write code,
//                  it will save much much much time. import thing should repeat　３　times　　　　　　
//        I, P = <read from user> ...
//        N, g, s, B = <read from server>
//        a = random()
//        A = g^a % N
//        u = SHA1(PAD(A) | PAD(B))
//        k = SHA1(N | PAD(g))
//        x = SHA1(s | SHA1(I | ":" | P))
//        <premaster secret> = (B - (k * g^x)) ^ (a + (u * x)) % N


     BIGNUM *m_rand_a;

    // k = SHA1(N | PAD(g)) -- tls-srp draft 8
    BIGNUM *Calc_k(BIGNUM *g,BIGNUM *N);
    BIGNUM* m_local_k;


    // clc public ephemeral value A
    //A = g^a,
    BIGNUM *Calc_A(BIGNUM *g,BIGNUM* a,BIGNUM *N);
    BIGNUM* m_local_A;

    //calculate the random scrambling parameter
    //Both:  u = H(A, B);

    BIGNUM *Calc_u(BIGNUM *A,BIGNUM *B,BIGNUM *N);
    BIGNUM* m_local_u;

    //User:  x = H(s,I, p)                 (user enters password)
    BIGNUM *Calc_x(BIGNUM *s,const char * uname,const char *p);
    BIGNUM* m_local_x;

    //User:  S = (B - kg^x) ^ (a + ux)   (computes session key)
    BIGNUM *Calc_S(BIGNUM *B,BIGNUM *k,BIGNUM *g,BIGNUM *a,BIGNUM *u,BIGNUM *x,BIGNUM *N);
    BIGNUM* m_local_s;

    //User:  K = H(S)
    BIGNUM* Calc_HashKey(BIGNUM *S);
    BIGNUM* m_local_hashkey;

//    hash is enough to proof in this simple system

//    //M = H(H(N) xor H(g), H(I), s, A, B, K) CALC PROOF PARAMETER
//    BIGNUM* Calc_ProofPara(BIGNUM* N,BIGNUM* g,BIGNUM* I,BIGNUM* s,BIGNUM* A,BIGNUM* B,BIGNUM* k);
//    BIGNUM*  m_local_proofpara;
//
//    //make proof
//    //H(A, M, K)
//    BIGNUM *Calc_Proof(BIGNUM *A,BIGNUM * M,BIGNUM *K);
//    BIGNUM* m_local_proof;

    //make Hash from data,return type BIGNUM
    //functional method
    BIGNUM *makeHash(BIGNUM *data1,BIGNUM *data2,const char* hashName);

protected:
public:
    /*N, g, and k are known beforehand to both client and server:*/
    //A large safe prime (N = 2q+1, where q is prime)
    //   All arithmetic is done modulo N.
    BIGNUM *m_base_N;

    //A generator modulo N
    BIGNUM *m_base_g;

    //Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
    BIGNUM *m_base_k;

        const char *username;
    const char *password;

    void set_username(const char *uname);
    void set_password(const char *pd);
};

#endif // CLIENTSIDE_H
