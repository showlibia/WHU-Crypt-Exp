#ifndef CRYPTO_H
#define CRYPTO_H

#pragma once

#include <cstdint>
#include <gmpxx.h>
#include <string>
#include <vector>

class CryptoManager {
public:
  CryptoManager();
  ~CryptoManager();

  mpz_class add(const mpz_class &a, const mpz_class &b);
  mpz_class subtract(const mpz_class &a, const mpz_class &b);
  mpz_class multiply(const mpz_class &a, const mpz_class &b);
  mpz_class mulMod(const mpz_class &a, const mpz_class &b, const mpz_class &m);
  mpz_class powMod(const mpz_class &base, const mpz_class &exp,
                   const mpz_class &mod);
  std::pair<mpz_class, mpz_class> divide(const mpz_class &a,
                                         const mpz_class &b);
  int compare(const mpz_class &a, const mpz_class &b);
  mpz_class hexTompz_class(const std::string &hex_str);
  std::string mpz_classToHex(const mpz_class &num);
  mpz_class getRandomRange(const mpz_class &min, const mpz_class &max);
  std::pair<mpz_class, mpz_class> extendedEuclidean(const mpz_class &a,
                                                    const mpz_class &b);

  struct RSAKeys {
    mpz_class e;
    mpz_class d;
    mpz_class n;
  };
  bool setPeerRSAKey(const mpz_class &e, const mpz_class &n);
  bool isPrime(const mpz_class &n);
  mpz_class signData(const mpz_class &data);
  bool verifySignature(const mpz_class &data, const mpz_class &signature);
  bool generateRSAKeys(size_t bits);
  mpz_class getRSAPublicKey_e() const;
  mpz_class getRSAPublicKey_n() const;

  bool generateDHParams();
  bool generateDHKeys();
  mpz_class computeSharedSecret(const mpz_class &peerPublic);
  mpz_class getDHPublicValue() const;

  std::string encryptAES(const std::string &plainText, const mpz_class &key);
  std::string decryptAES(const std::string &cipherText, const mpz_class &key);

private:
  gmp_randclass rng_;
  RSAKeys myRSAKeys, peerRSAKeys;

  struct DHParams {
    mpz_class P;
    mpz_class g;
    mpz_class secretExponent;
    mpz_class publicValue;
  } dhParams;

  bool isProbablePrime(const mpz_class &n, int rounds = 20);
  bool generatePrime(mpz_class &result, size_t bits);
  mpz_class getRandomBits(size_t bits);
  std::vector<uint8_t> getRandomBytes(size_t count);

  // 将 mpz_class 转换为指定长度的二进制向量
  std::vector<uint8_t> mpz_classToBinary(const mpz_class &number,
                                         size_t length);
};

#endif // CRYPTO_H
