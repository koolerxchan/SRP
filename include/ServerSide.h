#ifndef SERVERSIDE_H
#define SERVERSIDE_H
#include<string>
#include<iostream>
#include <openssl/bn.h>
#include <dlfcn.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <cstring>
#include <openssl/rand.h>
#include <NUM_gn.h>

#define print_bn(a) {fprintf(stderr, #a " = ");BN_print_fp(stderr,a);fprintf(stderr,"\n");}

using namespace std;

class ServerSide
{
public:
    ServerSide();
    virtual ~ServerSide();

// TODO (xchan#1#): N, g, s, v = <read from password file> ...
//        b = random()
//        k = SHA1(N | PAD(g))
//        B = k*v + g^b % N
//        A = <read from client>
//        u = SHA1(PAD(A) | PAD(B))
//        <premaster secret> = (A * v^u) ^ b % N

    BIGNUM *m_rand_b;
    //user's salt
    BIGNUM *m_rand_s;


    // k = SHA1(N | PAD(g)) -- tls-srp draft 8
    BIGNUM *Calc_k(BIGNUM *g,BIGNUM *N);
    BIGNUM* m_local_k;

    //get the B = kv + g^b
    BIGNUM *Calc_B(BIGNUM *k,BIGNUM *v,BIGNUM *g,BIGNUM*b,BIGNUM *N);
    BIGNUM *m_local_B;

    //calculate the random scrambling parameter
    //Both:  u = H(A, B);
    BIGNUM *Calc_u(BIGNUM *A,BIGNUM *B,BIGNUM *N);
    BIGNUM *m_local_u;

    //User:  x = H(s,I, p),
// TODO (xchan#1#): may be fixed if used in practice, here is more naive
    //here to be more simple ,just get x from the client
    //host store user  password
    BIGNUM *Calc_x(BIGNUM *s,const char * uname,const char *p);
    BIGNUM* m_local_x;

    //computes password verifierv
    //v = g^x
    BIGNUM *Calc_v(BIGNUM *g,BIGNUM *x,BIGNUM *N);
    BIGNUM *m_local_v;

    //computes session key
    //S = (Av^u) ^ b
    BIGNUM *Calc_SessionKey(BIGNUM *A,BIGNUM *v,BIGNUM *u,BIGNUM *b,BIGNUM *N);
    BIGNUM *m_local_s;

    //computes the hash of the session key
    //k=h(s)
    BIGNUM* Calc_HashKey(BIGNUM *S);
    BIGNUM *m_local_hashkey;

    //make proof
    //H(A, M, K),M comes from the client
    BIGNUM *Calc_Proof(BIGNUM *A,BIGNUM * M,BIGNUM *K);
    BIGNUM *m_local_proof;

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

#endif // SERVERSIDE_H
