#include "Crypto.h"
#include "AES.h"
#include <random>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <ctime>
#include <iostream>
#include <iomanip>

#define SHA256_ROTL(a, b) (((a >> (32 - b)) & (0x7fffffff >> (31 - b))) | (a << b))
#define SHA256_SR(a, b) ((a >> b) & (0x7fffffff >> (b - 1)))
#define SHA256_Ch(x, y, z) ((x & y) ^ ((~x) & z))
#define SHA256_Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA256_E0(x) (SHA256_ROTL(x, 30) ^ SHA256_ROTL(x, 19) ^ SHA256_ROTL(x, 10))
#define SHA256_E1(x) (SHA256_ROTL(x, 26) ^ SHA256_ROTL(x, 21) ^ SHA256_ROTL(x, 7))
#define SHA256_O0(x) (SHA256_ROTL(x, 25) ^ SHA256_ROTL(x, 14) ^ SHA256_SR(x, 3))
#define SHA256_O1(x) (SHA256_ROTL(x, 15) ^ SHA256_ROTL(x, 13) ^ SHA256_SR(x, 10))

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

const uint32_t SHA256::K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

SHA256::SHA256()
{
    init();
}

void SHA256::init()
{
    ctx.state[0] = 0x6a09e667;
    ctx.state[1] = 0xbb67ae85;
    ctx.state[2] = 0x3c6ef372;
    ctx.state[3] = 0xa54ff53a;
    ctx.state[4] = 0x510e527f;
    ctx.state[5] = 0x9b05688c;
    ctx.state[6] = 0x1f83d9ab;
    ctx.state[7] = 0x5be0cd19;
    ctx.count = 0;
}

void SHA256::transform(const unsigned char *data)
{
    uint32_t W[64];
    uint32_t A, B, C, D, E, F, G, H, T1, T2;
    int i;
    for (i = 0; i < 16; i++)
        W[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) |
               (data[i * 4 + 2] << 8) | (data[i * 4 + 3]);
    for (i = 16; i < 64; i++)
        W[i] = SHA256_O1(W[i - 2]) + W[i - 7] + SHA256_O0(W[i - 15]) + W[i - 16];
    A = ctx.state[0];
    B = ctx.state[1];
    C = ctx.state[2];
    D = ctx.state[3];
    E = ctx.state[4];
    F = ctx.state[5];
    G = ctx.state[6];
    H = ctx.state[7];
    for (i = 0; i < 64; i++)
    {
        T1 = H + SHA256_E1(E) + SHA256_Ch(E, F, G) + K[i] + W[i];
        T2 = SHA256_E0(A) + SHA256_Maj(A, B, C);
        H = G;
        G = F;
        F = E;
        E = D + T1;
        D = C;
        C = B;
        B = A;
        A = T1 + T2;
    }
    ctx.state[0] += A;
    ctx.state[1] += B;
    ctx.state[2] += C;
    ctx.state[3] += D;
    ctx.state[4] += E;
    ctx.state[5] += F;
    ctx.state[6] += G;
    ctx.state[7] += H;
}

void SHA256::update(const unsigned char *data, size_t len)
{
    uint32_t left = ctx.count % 64;
    uint32_t fill = 64 - left;
    ctx.count += len;
    if (left && len >= fill)
    {
        std::memcpy(ctx.buffer + left, data, fill);
        transform(ctx.buffer);
        data += fill;
        len -= fill;
        left = 0;
    }
    while (len >= 64)
    {
        transform(data);
        data += 64;
        len -= 64;
    }
    if (len > 0)
    {
        std::memcpy(ctx.buffer + left, data, len);
    }
}

void SHA256::final(unsigned char *digest)
{
    uint32_t left = ctx.count % 64;
    uint64_t bits = static_cast<uint64_t>(ctx.count) * 8;
    ctx.buffer[left++] = 0x80;
    if (left > 56)
    {
        std::memset(ctx.buffer + left, 0, 64 - left);
        transform(ctx.buffer);
        left = 0;
    }
    std::memset(ctx.buffer + left, 0, 56 - left);
    ctx.buffer[56] = static_cast<unsigned char>((bits >> 56) & 0xff);
    ctx.buffer[57] = static_cast<unsigned char>((bits >> 48) & 0xff);
    ctx.buffer[58] = static_cast<unsigned char>((bits >> 40) & 0xff);
    ctx.buffer[59] = static_cast<unsigned char>((bits >> 32) & 0xff);
    ctx.buffer[60] = static_cast<unsigned char>((bits >> 24) & 0xff);
    ctx.buffer[61] = static_cast<unsigned char>((bits >> 16) & 0xff);
    ctx.buffer[62] = static_cast<unsigned char>((bits >> 8) & 0xff);
    ctx.buffer[63] = static_cast<unsigned char>(bits & 0xff);

    transform(ctx.buffer);

    for (int i = 0; i < 8; i++)
    {
        digest[i * 4] = (ctx.state[i] >> 24) & 0xff;
        digest[i * 4 + 1] = (ctx.state[i] >> 16) & 0xff;
        digest[i * 4 + 2] = (ctx.state[i] >> 8) & 0xff;
        digest[i * 4 + 3] = ctx.state[i] & 0xff;
    }
}

std::vector<unsigned char> SHA256::hash(const unsigned char *input, size_t length)
{
    init();
    update(input, length);
    std::vector<unsigned char> digest(DIGEST_SIZE);
    final(digest.data());
    return digest;
}

std::string CryptoManager::encryptAES(const std::string &plainText,
                                      const std::vector<uint8_t> &key)
{
    std::vector<uint8_t> plain_bytes(plainText.begin(), plainText.end());

    std::vector<uint8_t> encrypted_bytes = AESNI::encrypt(plain_bytes, key);

    return std::string(encrypted_bytes.begin(), encrypted_bytes.end());
}

std::string CryptoManager::decryptAES(const std::string &cipherText,
                                      const std::vector<uint8_t> &key)
{
    std::vector<uint8_t> cipher_bytes(cipherText.begin(), cipherText.end());

    std::vector<uint8_t> decrypted_bytes = AESNI::decrypt(cipher_bytes, key);

    return std::string(decrypted_bytes.begin(), decrypted_bytes.end());
}

std::string SHA256::bytesToHex(const std::vector<unsigned char> &bytes)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char byte : bytes)
    {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

bool SHA256::test()
{
    const unsigned char empty[] = "";
    const unsigned char abc[] = "abc";
    const unsigned char long_str[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    bool pass = true;
    std::vector<unsigned char> result = hash(empty, 0);
    std::string hash1 = bytesToHex(result);
    if (hash1 != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    {
        std::cout << "Test vector 1 failed\n";
        pass = false;
    }
    result = hash(abc, 3);
    std::string hash2 = bytesToHex(result);
    if (hash2 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    {
        std::cout << "Test vector 2 failed\n";
        pass = false;
    }
    result = hash(long_str, 56);
    std::string hash3 = bytesToHex(result);
    if (hash3 != "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    {
        std::cout << "Test vector 3 failed\n";
        pass = false;
    }
    return pass;
}
