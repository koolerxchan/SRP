/*The MIT License (MIT)

Copyright (c) [year] [xchan]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.*/

#include <iostream>
#include "ServerSide.h"
#include "ClientSide.h"


using namespace std;
static const char *username = "username123";
static const char *password = "password123";

int main()
{
    ServerSide *server = new ServerSide();
    ClientSide *client = new ClientSide();
    server->set_username(username);
    server->set_password(password);
    client->set_username(username);
    client->set_password(password);
    cout<<"0.the server read file information:N,g,s,v"<<endl;
    server->m_local_k = server->Calc_k(server->m_base_g,server->m_base_N);
    //print_bn(server->m_local_k);
    server->m_local_x = server->Calc_x(server->m_rand_s,server->username,server->password);
    //print_bn(server->m_local_x);
    server->m_local_v = server->Calc_v(server->m_base_g,server->m_local_x,server->m_base_N);
    print_bn(server->m_base_N);
    print_bn(server->m_base_g);
    print_bn(server->m_rand_s);
    print_bn(server->m_local_v);
    cout<<endl;

    cout<<"1. client sends username I and public ephemeral value A to the server"<<endl;
    client->m_local_A = client->Calc_A(client->m_base_g,client->m_rand_a,client->m_base_N);
    cout<<"username="<<client->username<<endl;
    print_bn(client->m_local_A);
    cout<<endl;

    cout<<"2. server sends user's salt s and public ephemeral value B to client"<<endl;
    print_bn(server->m_rand_s);
    server->m_local_B = server->Calc_B(server->m_local_k,server->m_local_v,server->m_base_g,server->m_rand_b,server->m_base_N);
    print_bn(server->m_local_B);
    cout<<endl;

    cout<<"3. client and server calculate the random scrambling parameter"<<endl;
    server->m_local_u = server->Calc_u(client->m_local_A,server->m_local_B,server->m_base_N);
    client->m_local_u = client->Calc_u(client->m_local_A,server->m_local_B,client->m_base_N);
    print_bn(server->m_local_u );
    print_bn(client->m_local_u );
    cout<<endl;

    cout<<"4. client computes session key"<<endl;
    client->m_local_x = client->Calc_x(server->m_rand_s,client->username,client->password);
    client->m_local_k = client->Calc_k(client->m_base_g,client->m_base_N);
    client->m_local_s = client->Calc_S(server->m_local_B,client->m_local_k,client->m_base_g,client->m_rand_a,client->m_local_u,client->m_local_x,client->m_base_N);
    print_bn(client->m_local_x);
    print_bn(client->m_local_k);
    print_bn(client->m_local_s);
    cout<<endl;

    cout<<"5. server computes session key"<<endl;
    server->m_local_s = server->Calc_SessionKey(client->m_local_A,server->m_local_v,server->m_local_u,server->m_rand_b,server->m_base_N);
    print_bn(server->m_local_s);
    cout<<endl;

    cout<<"6. compare the seesion key hash"<<endl;
    server->m_local_hashkey = server->Calc_HashKey(server->m_local_s);
    client->m_local_hashkey = client->Calc_HashKey(client->m_local_s);
    int cmp = BN_cmp(server->m_local_hashkey,client->m_local_hashkey);
    print_bn(server->m_local_hashkey);
    print_bn(client->m_local_hashkey);
    cout<<"cmp = BN_cmp(server->m_local_hashkey,client->m_local_hashkey)="<<cmp<<endl;


    return 0;
}
