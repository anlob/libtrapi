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
#if (_TEST_ALL == 1) || (_TEST_GRP_COMMON == 1) || (_TEST_COMMON_HMAC_SHA512 == 1)
void test_common_hmac_sha512()
{
  vector<unsigned char> data = {
    '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
    '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
    '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
    '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
    '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
  };
  vector<unsigned char> key = { 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y' };
  vector<unsigned char> digest;
  hmac_sha512(&digest, data, key);

  if (digest.size() != 64)
    logexc << "hmac_sha512() returned bad digest length" << endl;
  if (memcmp(digest.data(), "\x24\x18\xf1\x94\xf9\x2c\xf3\xd1\xaa\xcc\x67\xf7\x6e\x63\xd8\x9a\x80\x86\x4e\x06\x6f\x13\x3c\xd4\x6c\x73\x7d\x72\x58\x9a\x81\x84\x7c\x94\x2c\xd5\x6b\xa6\x45\x7a\xb0\x3d\x5d\xb3\x2a\x54\x19\x2f\xd9\x9a\xb5\xf8\x20\x1d\x0e\x7d\xa9\x70\x82\x28\x5f\x83\x15\x93", 64) != 0)
    logexc << "hmac_sha512() returned bad digest data" << endl;
}
#endif
#if (_TEST_ALL == 1) || (_TEST_GRP_COMMON == 1) || (_TEST_COMMON_HMAC_SHA256 == 1)
void test_common_hmac_sha256()
{
  vector<unsigned char> data = {
    '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
    '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
    '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
    '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
    '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
  };
  vector<unsigned char> key = { 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y' };
  vector<unsigned char> digest;
  hmac_sha256(&digest, data, key);

  if (digest.size() != 32)
    logexc << "hmac_sha256() returned bad digest length" << endl;
  if (memcmp(digest.data(), "\xed\x5b\x8c\x40\x88\xca\x2b\xd2\x7c\xc9\x72\xd5\x19\xc9\x54\xbe\xbd\x15\x0c\xcd\xa6\x03\x2b\x5f\x7c\x04\x89\x16\x37\xd2\x1c\xbc", 32) != 0)
    logexc << "hmac_sha256() returned bad digest data" << endl;
}
#endif
#if (_TEST_ALL == 1) || (_TEST_GRP_COMMON == 1) || (_TEST_COMMON_B64_ENCODE == 1)
void test_common_b64_encode()
{
  vector<unsigned char> data = {
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
  vector<unsigned char> buf;
  b64_decode(&buf, data);
  if ((buf.size() != 80) || (memcmp(buf.data(), "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 80) != 0))
    logexc << "b64_decode() returned bad decode" << endl;
}
#endif
