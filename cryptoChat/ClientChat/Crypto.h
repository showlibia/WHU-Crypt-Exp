#ifndef CRYPTO_H
#define CRYPTO_H

#pragma once

#include <gmpxx.h>
#include <vector>
#include <string>
#include <cstdint>

class SHA256
{
private:
    struct Context
    {
        uint32_t state[8];
        uint64_t count;
        unsigned char buffer[64];
    };

    static const uint32_t K[64];
    Context ctx;

    void init();
    void transform(const unsigned char *data);

public:
    static const int DIGEST_SIZE = 32;

    SHA256();

    void update(const unsigned char *data, size_t len);
    void final(unsigned char *digest);
    std::string bytesToHex(const std::vector<unsigned char> &bytes);
    bool test();
    std::vector<unsigned char> hash(const unsigned char* input, size_t length);

};

class CryptoManager
{
public:
    CryptoManager();
    ~CryptoManager();

    mpz_class add(const mpz_class &a, const mpz_class &b);
    mpz_class subtract(const mpz_class &a, const mpz_class &b);
    mpz_class multiply(const mpz_class &a, const mpz_class &b);
    mpz_class mulMod(const mpz_class &a, const mpz_class &b, const mpz_class &m);
    mpz_class powMod(const mpz_class &base, const mpz_class &exp, const mpz_class &mod);
    std::pair<mpz_class, mpz_class> divide(const mpz_class &a, const mpz_class &b);
    int compare(const mpz_class &a, const mpz_class &b);
    mpz_class hexTompz_class(const std::string &hex_str);
    std::string mpz_classToHex(const mpz_class &num);
    mpz_class getRandomRange(const mpz_class &min, const mpz_class &max);
    std::pair<mpz_class, mpz_class> extendedEuclidean(const mpz_class &a, const mpz_class &b);

    struct RSAKeys
    {
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

    std::string encryptAES(const std::string &plainText,
                           const std::vector<uint8_t> &key);
    std::string decryptAES(const std::string &cipherText,
                           const std::vector<uint8_t> &key);

    bool saveServerKey(const mpz_class& e, const mpz_class& n);
    bool verifyServerKey(const mpz_class& e, const mpz_class& n);
    bool hasStoredServerKey();

private:
    gmp_randclass rng_;
    RSAKeys myRSAKeys, peerRSAKeys;

    struct DHParams
    {
        mpz_class P;
        mpz_class g;
        mpz_class secretExponent;
        mpz_class publicValue;
    } dhParams;

    bool isProbablePrime(const mpz_class &n, int rounds = 20);
    bool generatePrime(mpz_class &result, size_t bits);
    mpz_class getRandomBits(size_t bits);
    std::vector<uint8_t> getRandomBytes(size_t count);
    static const std::string SERVER_KEY_FILE;
};

#endif // CRYPTO_H
