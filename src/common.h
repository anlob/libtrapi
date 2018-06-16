/** \file common.h
 * Common stuff.
 *
 * \author Andreas Lobbes, andreas.lobbes@gmail.com
 * \date 2018
 * \copyright GPLV3 and above
 * \copyright GCC RTL Exception 3.1 applies to any former and current copyright holder
 * \see LICENSES at top level directory
 * \see http://www.gnu.org/licenses
 */
#ifndef COMMON_H_INCLUDED
#define COMMON_H_INCLUDED

#include <string>
#include <vector>


namespace trapi {

const std::vector<unsigned char> &sha256(std::vector<unsigned char> *digest, const std::string &data);
const std::vector<unsigned char> &hmac_sha512(std::vector<unsigned char> *digest, const std::vector<unsigned char> &data, const std::vector<unsigned char> &key);
const std::vector<unsigned char> &hmac_sha256(std::vector<unsigned char> *digest, const std::vector<unsigned char> &data, const std::vector<unsigned char> &key);
const std::string &b64_encode(std::string *buf, const std::vector<unsigned char> &data);
const std::vector<unsigned char> &b64_decode(std::vector<unsigned char> *buf, const std::string &data);

};


#endif // COMMON_H_INCLUDED
