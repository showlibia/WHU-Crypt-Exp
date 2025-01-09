#include "Crypto.h"
#include <random>
#include <fstream>
#include <stdexcept>
#include <cstring>
#include <ctime>
#include <iostream>

std::vector<uint8_t> CryptoManager::getRandomBytes(size_t count)
{
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (!urandom)
    {
        throw std::runtime_error("Failed to open /dev/urandom");
    }
    std::vector<uint8_t> buffer(count);
    urandom.read(reinterpret_cast<char *>(buffer.data()), count);
    return buffer;
}

CryptoManager::CryptoManager()
    : rng_(gmp_randinit_default)
{
    std::random_device rd;
    std::vector<unsigned int> seed_data(8);
    for (auto &val : seed_data)
    {
        val = rd();
    }
    unsigned long seed_ulong = 0;
    for (auto val : seed_data)
    {
        seed_ulong = (seed_ulong << 5) ^ val;
    }
    rng_.seed(seed_ulong);
    if (!generateDHParams())
    {
        throw std::runtime_error("Failed to generate DH parameters");
    }
}

CryptoManager::~CryptoManager()
{
}

mpz_class CryptoManager::getRSAPublicKey_e() const
{
    return myRSAKeys.e;
}

mpz_class CryptoManager::getRSAPublicKey_n() const
{
    return myRSAKeys.n;
}

mpz_class CryptoManager::add(const mpz_class &a, const mpz_class &b)
{
    return a + b;
}

mpz_class CryptoManager::subtract(const mpz_class &a, const mpz_class &b)
{
    if (a < b)
    {
        throw std::runtime_error("Negative result in subtraction");
    }
    return a - b;
}

mpz_class CryptoManager::multiply(const mpz_class &a, const mpz_class &b)
{
    return a * b;
}

mpz_class CryptoManager::mulMod(const mpz_class &a, const mpz_class &b, const mpz_class &m)
{
    return (a * b) % m;
}

mpz_class CryptoManager::powMod(const mpz_class &base, const mpz_class &exp, const mpz_class &mod)
{
    mpz_class result;
    mpz_powm(result.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
    return result;
}

std::pair<mpz_class, mpz_class> CryptoManager::divide(const mpz_class &a, const mpz_class &b)
{
    if (b == 0)
    {
        throw std::runtime_error("Division by zero");
    }
    mpz_class quotient, remainder;
    mpz_fdiv_qr(quotient.get_mpz_t(), remainder.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t());
    return {quotient, remainder};
}

int CryptoManager::compare(const mpz_class &a, const mpz_class &b)
{
    if (a < b)
    {
        return -1;
    }
    if (a > b)
    {
        return 1;
    }
    return 0;
}

mpz_class CryptoManager::hexTompz_class(const std::string &hex_str)
{
    mpz_class result;
    if (mpz_set_str(result.get_mpz_t(), hex_str.c_str(), 16) != 0)
    {
        throw std::runtime_error("Invalid hex string");
    }
    return result;
}

std::string CryptoManager::mpz_classToHex(const mpz_class &num)
{
    char *hex_str = mpz_get_str(NULL, 16, num.get_mpz_t());
    std::string result(hex_str);
    free(hex_str);
    return result;
}

mpz_class CryptoManager::getRandomRange(const mpz_class &min, const mpz_class &max)
{
    if (max <= min)
    {
        throw std::invalid_argument("max must be greater than min");
    }
    mpz_class range = max - min;
    mpz_class rand;
    size_t bits = mpz_sizeinbase(range.get_mpz_t(), 2);
    do
    {
        rand = rng_.get_z_bits(bits);
    } while (rand >= range);
    return min + rand;
}

std::pair<mpz_class, mpz_class> CryptoManager::extendedEuclidean(const mpz_class &a, const mpz_class &b)
{
    mpz_class gcd, x, y;
    mpz_gcdext(gcd.get_mpz_t(), x.get_mpz_t(), y.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t());
    return {x, y};
}

bool CryptoManager::setPeerRSAKey(const mpz_class &e, const mpz_class &n)
{
    if (e <= 0 || n <= 1)
    {
        std::cerr << "Invalid peer RSA key parameters" << std::endl;
        return false;
    }
    peerRSAKeys.e = e;
    peerRSAKeys.n = n;
    return true;
}

bool CryptoManager::isPrime(const mpz_class &n)
{
    return isProbablePrime(n, 20);
}

mpz_class CryptoManager::signData(const mpz_class &data)
{
    mpz_class message = data % myRSAKeys.n;
    mpz_class signature = powMod(message, myRSAKeys.d, myRSAKeys.n);
    mpz_class check = powMod(signature, myRSAKeys.e, myRSAKeys.n);
    if (check != message)
    {
        throw std::runtime_error("Invalid signature generated");
    }
    return signature;
}

bool CryptoManager::verifySignature(const mpz_class &data, const mpz_class &signature)
{
    try
    {
        mpz_class message = data % peerRSAKeys.n;
        mpz_class decrypted = powMod(signature, peerRSAKeys.e, peerRSAKeys.n);
        return (decrypted == message);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Verification error: " << e.what() << std::endl;
        return false;
    }
}

bool CryptoManager::generateRSAKeys(size_t bits)
{
    mpz_class p, q;
    if (!generatePrime(p, bits / 2) || !generatePrime(q, bits / 2))
    {
        std::cout << "Failed to generate prime numbers for RSA" << std::endl;
        return false;
    }
    myRSAKeys.n = multiply(p, q);
    mpz_class p_1 = subtract(p, 1);
    mpz_class q_1 = subtract(q, 1);
    mpz_class phi = multiply(p_1, q_1);
    myRSAKeys.e = 65537;
    mpz_class d;
    if (mpz_invert(d.get_mpz_t(), myRSAKeys.e.get_mpz_t(), phi.get_mpz_t()) == 0)
    {
        std::cout << "Failed to compute private key - no modular inverse exists" << std::endl;
        return false;
    }
    myRSAKeys.d = d;
    if (d < 0)
    {
        d += phi;
    }
    mpz_class check = (myRSAKeys.e * d) % phi;
    if (check != 1)
    {
        std::cout << "Key generation failed: e*d != 1 mod phi(n)" << std::endl;
        return false;
    }
    try
    {
        mpz_class test_data("12be557bc4548dfe8d5cc5489bc444b6529e4661dd298bc2dc68916d5b41307b2db8df70d95a71cf605ee53936e7fbef1d87db36bf863d347c64ee05c728add3fba4b558bcd0f91add5dd6d5f95b05598b890f5bc6227ad954568fa6e0e1971aad2ae33c6f30367dcfe8b457deaffda5d8a2cbba31bf07785ab82f9467b33307dead2637f9a926710be7cf3a3e2e18c1fa78069082e4640e53aa291678bc0c2c0fefbb520564150a9237cac61bcb5199c7e183a13be35cc6ce4f0fa0e4a8970b795998fba26969cc8dc0db367f71f154dcd8c9f79bfbe9417d1282a3104eaa8908666e50032c444ea66b3edf23dfdacb8dc40bd0cd0c878661310b44ab9d9563", 16);
        test_data = test_data % myRSAKeys.n;
        mpz_class signature = powMod(test_data, myRSAKeys.d, myRSAKeys.n);
        mpz_class decrypted = powMod(signature, myRSAKeys.e, myRSAKeys.n);
        if (decrypted != test_data)
        {
            std::cout << "RSA key pair verification failed!" << std::endl;
            return false;
        }
    }
    catch (const std::exception &e)
    {
        std::cout << "RSA key verification error: " << e.what() << std::endl;
        return false;
    }

    return true;
}

bool CryptoManager::generateDHParams()
{
    static const char *P_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                               "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                               "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                               "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                               "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                               "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                               "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                               "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                               "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                               "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                               "15728E5A8AACAA68FFFFFFFFFFFFFFFF";
    dhParams.P = hexTompz_class(P_hex);
    dhParams.g = 2;
    return true;
}

bool CryptoManager::generateDHKeys()
{
    dhParams.secretExponent = getRandomRange(2, dhParams.P - 2);
    dhParams.publicValue = powMod(dhParams.g, dhParams.secretExponent, dhParams.P);
    return true;
}

mpz_class CryptoManager::computeSharedSecret(const mpz_class &peerPublic)
{
    return powMod(peerPublic, dhParams.secretExponent, dhParams.P);
}

mpz_class CryptoManager::getRandomBits(size_t bits)
{
    return rng_.get_z_bits(bits);
}

bool CryptoManager::isProbablePrime(const mpz_class &n, int rounds)
{
    return mpz_probab_prime_p(n.get_mpz_t(), rounds) > 0;
}

bool CryptoManager::generatePrime(mpz_class &result, size_t bits)
{
    const int MAX_ATTEMPTS = 5000;
    int attempts = 0;
    while (attempts < MAX_ATTEMPTS)
    {
        result = rng_.get_z_bits(bits);
        mpz_setbit(result.get_mpz_t(), bits - 1);
        if (isProbablePrime(result))
        {
            return true;
        }
        attempts++;
    }
    return false;
}

mpz_class CryptoManager::getDHPublicValue() const
{
    return dhParams.publicValue;
}