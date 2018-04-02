#include "common.h"
#include "../libcpp-core/src/Log.h"
#include "../libcpp-core/src/SSL.h"

using namespace std;
using namespace trapi;


const std::vector<unsigned char> &trapi::sha256(std::vector<unsigned char> *digest, const std::string &data)
{
  SSLInit sslInit;

  digest->resize(SHA256_DIGEST_LENGTH);

  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, data.c_str(), data.length());
  SHA256_Final(digest->data(), &ctx);

  return *digest;
}

const std::vector<unsigned char> &trapi::hmac_sha512(std::vector<unsigned char> *digest, const std::vector<unsigned char> &data, const std::vector<unsigned char> &key)
{
   unsigned int len = EVP_MAX_MD_SIZE;
   digest->resize(len);

   HMAC_CTX *ctx = HMAC_CTX_new();
   //HMAC_CTX_init(&ctx);

   HMAC_Init_ex(ctx, key.data(), key.size(), EVP_sha512(), NULL);
   HMAC_Update(ctx, data.data(), data.size());
   HMAC_Final(ctx, digest->data(), &len);

   HMAC_CTX_free(ctx);
   //HMAC_CTX_cleanup(&ctx);

   return *digest;
}

const std::string &trapi::b64_encode(std::string *buf, const std::vector<unsigned char> &data)
{
  SSLInit sslInit;

  BIO *b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

  BIO *bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);

  BIO_write(b64, data.data(), data.size());
  BIO_flush(b64);

  BUF_MEM *bptr = NULL;
  BIO_get_mem_ptr(b64, &bptr);

  buf->resize(bptr->length);
  buf->assign((const char *) bptr->data, bptr->length);
  BIO_free_all(b64);

  return *buf;
}

const std::vector<unsigned char> &trapi::b64_decode(std::vector<unsigned char> *buf, const std::string &data)
{
  SSLInit sslInit;

  BIO* b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

  BIO* bmem = BIO_new_mem_buf((void *) data.c_str(), data.length());
  bmem = BIO_push(b64, bmem);

  buf->resize(data.length());
  int decoded_size = BIO_read(bmem, (char *) buf->data(), buf->size());
  BIO_free_all(bmem);

  if (decoded_size < 0)
    logexc << "failed to decode b64 string \"" << data << "\"" << endl;
  buf->resize((unsigned) decoded_size);

  return *buf;
}
