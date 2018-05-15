#include <cstring>
#include "../libcpp-core/src/Log.h"
#include "common.h"
#include "../src/common.h"

using namespace std;
using namespace trapi;


#if (_TEST_ALL == 1) || (_TEST_GRP_COMMON == 1) || (_TEST_COMMON_SHA256 == 1)
void test_common_sha256()
{
  vector<unsigned char> digest;
  sha256(&digest, "what a wonderful world");
  if (digest.size() != 32)
    logexc << "sha4256() returned bad digest length" << endl;
  if (memcmp(digest.data(), "\x83\xd7\x3b\x19\x03\x8d\x57\x44\xc2\x66\x84\x4d\xd9\xd0\x02\x6f\x71\xb0\xc7\x23\xb3\xaf\x41\xed\x46\xaf\xa9\x10\x44\xf9\xa9\xcb", 32) != 0)
    logexc << "sha4256() returned bad digest data" << endl;
}
#endif
#if (_TEST_ALL == 1) || (_TEST_GRP_COMMON == 1) || (_TEST_COMMON_HMAC_SHA256 == 1)
void test_common_hmac_sha256()
{

}
#endif
#if (_TEST_ALL == 1) || (_TEST_GRP_COMMON == 1) || (_TEST_COMMON_B64_ENCODE == 1)
void test_common_b64_encode()
{
    std::vector<unsigned char> data = {
        '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
        '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
        '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
        '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
        '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
    };
    string buf;
    if (b64_encode(&buf, data) != "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
        logexc << "b64_encode() returned bad encode" << endl;
}
#endif
#if (_TEST_ALL == 1) || (_TEST_GRP_COMMON == 1) || (_TEST_COMMON_B64_DECODE == 1)
void test_common_b64_decode()
{
    string data = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    std::vector<unsigned char> buf;
    b64_decode(&buf, data);
    if ((buf.size() != 80) || (memcmp(buf.data(), "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 80) != 0))
        logexc << "b64_decode() returned bad decode" << endl;
}
#endif
