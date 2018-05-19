#include "conf.h"
#include "common.h"

using namespace std;


int main()
{
#if (_TEST_ALL == 1) || (_TEST_GRP_COMMON == 1) || (_TEST_COMMON_SHA256 == 1)
  test_common_sha256();
#endif
#if (_TEST_ALL == 1) || (_TEST_GRP_COMMON == 1) || (_TEST_COMMON_HMAC_SHA512 == 1)
  test_common_hmac_sha512();
#endif
#if (_TEST_ALL == 1) || (_TEST_GRP_COMMON == 1) || (_TEST_COMMON_HMAC_SHA256 == 1)
  test_common_hmac_sha256();
#endif
#if (_TEST_ALL == 1) || (_TEST_GRP_COMMON == 1) || (_TEST_COMMON_B64_ENCODE == 1)
  test_common_b64_encode();
#endif
#if (_TEST_ALL == 1) || (_TEST_GRP_COMMON == 1) || (_TEST_COMMON_B64_DECODE == 1)
  test_common_b64_decode();
#endif

  return 0;
}
