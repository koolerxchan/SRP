#ifndef NUM_GN_INCLUDED
#define NUM_GN_INCLUDED
#include <openssl/bn.h>
# if (BN_BYTES == 8)
#  if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
#   define bn_pack4(a1,a2,a3,a4) ((a1##UI64<<48)|(a2##UI64<<32)|(a3##UI64<<16)|a4##UI64)
#  elif defined(__arch64__)
#   define bn_pack4(a1,a2,a3,a4) ((a1##UL<<48)|(a2##UL<<32)|(a3##UL<<16)|a4##UL)
#  else
#   define bn_pack4(a1,a2,a3,a4) ((a1##ULL<<48)|(a2##ULL<<32)|(a3##ULL<<16)|a4##ULL)
#  endif
# elif (BN_BYTES == 4)
#  define bn_pack4(a1,a2,a3,a4)  ((a3##UL<<16)|a4##UL), ((a1##UL<<16)|a2##UL)
# else
#  error "unsupported BN_BYTES"
# endif


static BN_ULONG bn_generator_2_value[] = { 2 };

static BIGNUM bn_generator_2 =
{
    bn_generator_2_value,
    1,
    1,
    0,
    BN_FLG_STATIC_DATA
};
static BN_ULONG bn_group_1024_value[] =
{
    bn_pack4(0x9FC6, 0x1D2F, 0xC0EB, 0x06E3),
    bn_pack4(0xFD51, 0x38FE, 0x8376, 0x435B),
    bn_pack4(0x2FD4, 0xCBF4, 0x976E, 0xAA9A),
    bn_pack4(0x68ED, 0xBC3C, 0x0572, 0x6CC0),
    bn_pack4(0xC529, 0xF566, 0x660E, 0x57EC),
    bn_pack4(0x8255, 0x9B29, 0x7BCF, 0x1885),
    bn_pack4(0xCE8E, 0xF4AD, 0x69B1, 0x5D49),
    bn_pack4(0x5DC7, 0xD7B4, 0x6154, 0xD6B6),
    bn_pack4(0x8E49, 0x5C1D, 0x6089, 0xDAD1),
    bn_pack4(0xE0D5, 0xD8E2, 0x50B9, 0x8BE4),
    bn_pack4(0x383B, 0x4813, 0xD692, 0xC6E0),
    bn_pack4(0xD674, 0xDF74, 0x96EA, 0x81D3),
    bn_pack4(0x9EA2, 0x314C, 0x9C25, 0x6576),
    bn_pack4(0x6072, 0x6187, 0x75FF, 0x3C0B),
    bn_pack4(0x9C33, 0xF80A, 0xFA8F, 0xC5E8),
    bn_pack4(0xEEAF, 0x0AB9, 0xADB3, 0x8DD6)
};

static BIGNUM bn_group_1024 = {
        bn_group_1024_value,
        (sizeof bn_group_1024_value) / sizeof(BN_ULONG),
        (sizeof bn_group_1024_value) / sizeof(BN_ULONG),
        0,
        BN_FLG_STATIC_DATA
    };


#endif // NUM_GN_INCLUDED2
