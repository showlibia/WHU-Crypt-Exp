#include "AES.h"
#include <wmmintrin.h>
#include <iostream>

namespace
{
    constexpr uint8_t round_const[10] = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

    static __m128i aes_128_key_expansion(__m128i key, __m128i keygened)
    {
        keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        return _mm_xor_si128(key, keygened);
    }
#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))
}

std::vector<uint8_t> AESNI::encrypt(const std::vector<uint8_t> &plainText,
                                    const std::vector<uint8_t> &key)
{
    if (key.size() != 16)
    {
        throw std::invalid_argument("Key size must be 16 bytes for AES-128");
    }
    __m128i key_schedule[11];
    key_schedule[0] = _mm_loadu_si128((__m128i *)key.data());
    key_schedule[1] = AES_128_key_exp(key_schedule[0], 0x01);
    key_schedule[2] = AES_128_key_exp(key_schedule[1], 0x02);
    key_schedule[3] = AES_128_key_exp(key_schedule[2], 0x04);
    key_schedule[4] = AES_128_key_exp(key_schedule[3], 0x08);
    key_schedule[5] = AES_128_key_exp(key_schedule[4], 0x10);
    key_schedule[6] = AES_128_key_exp(key_schedule[5], 0x20);
    key_schedule[7] = AES_128_key_exp(key_schedule[6], 0x40);
    key_schedule[8] = AES_128_key_exp(key_schedule[7], 0x80);
    key_schedule[9] = AES_128_key_exp(key_schedule[8], 0x1B);
    key_schedule[10] = AES_128_key_exp(key_schedule[9], 0x36);
    std::vector<uint8_t> paddedText = plainText;
    size_t padding_len = 16 - (plainText.size() % 16);
    if (padding_len == 0)
    {
        padding_len = 16;
    }
    paddedText.insert(paddedText.end(), padding_len, padding_len);
    std::vector<uint8_t> cipherText(paddedText.size());
    __m128i block;
    for (size_t i = 0; i < paddedText.size(); i += 16)
    {
        block = _mm_loadu_si128((__m128i *)&paddedText[i]);

        block = _mm_xor_si128(block, key_schedule[0]);
        for (int round = 1; round < 10; ++round)
        {
            block = _mm_aesenc_si128(block, key_schedule[round]);
        }
        block = _mm_aesenclast_si128(block, key_schedule[10]);

        _mm_storeu_si128((__m128i *)&cipherText[i], block);
    }
    return cipherText;
}

std::vector<uint8_t> AESNI::decrypt(const std::vector<uint8_t> &cipherText,
                                    const std::vector<uint8_t> &key)
{
    if (key.size() != 16)
    {
        throw std::invalid_argument("Key size must be 16 bytes for AES-128");
    }
    if (cipherText.size() % 16 != 0)
    {
        throw std::invalid_argument("Cipher text size must be a multiple of 16 bytes");
    }
    __m128i key_schedule[11];
    __m128i dec_key_schedule[11];
    key_schedule[0] = _mm_loadu_si128((__m128i *)key.data());
    key_schedule[1] = AES_128_key_exp(key_schedule[0], 0x01);
    key_schedule[2] = AES_128_key_exp(key_schedule[1], 0x02);
    key_schedule[3] = AES_128_key_exp(key_schedule[2], 0x04);
    key_schedule[4] = AES_128_key_exp(key_schedule[3], 0x08);
    key_schedule[5] = AES_128_key_exp(key_schedule[4], 0x10);
    key_schedule[6] = AES_128_key_exp(key_schedule[5], 0x20);
    key_schedule[7] = AES_128_key_exp(key_schedule[6], 0x40);
    key_schedule[8] = AES_128_key_exp(key_schedule[7], 0x80);
    key_schedule[9] = AES_128_key_exp(key_schedule[8], 0x1B);
    key_schedule[10] = AES_128_key_exp(key_schedule[9], 0x36);
    dec_key_schedule[0] = key_schedule[10];
    for (int i = 1; i < 10; ++i)
    {
        dec_key_schedule[i] = _mm_aesimc_si128(key_schedule[10 - i]);
    }
    dec_key_schedule[10] = key_schedule[0];
    std::vector<uint8_t> plainText(cipherText.size());
    __m128i block;
    for (size_t i = 0; i < cipherText.size(); i += 16)
    {
        block = _mm_loadu_si128((__m128i *)&cipherText[i]);

        block = _mm_xor_si128(block, dec_key_schedule[0]);
        for (int round = 1; round < 10; ++round)
        {
            block = _mm_aesdec_si128(block, dec_key_schedule[round]);
        }
        block = _mm_aesdeclast_si128(block, dec_key_schedule[10]);

        _mm_storeu_si128((__m128i *)&plainText[i], block);
    }
    size_t padding_len = plainText.back();
    if (padding_len == 0 || padding_len > 16)
    {
        throw std::invalid_argument("Invalid padding: bad length");
    }

    if (plainText.size() < padding_len)
    {
        throw std::invalid_argument("Invalid padding: text too short");
    }
    size_t padding_start = plainText.size() - padding_len;
    for (size_t i = padding_start; i < plainText.size(); ++i)
    {
        if (plainText[i] != padding_len)
        {
            throw std::invalid_argument("Invalid padding: wrong byte value");
        }
    }
    plainText.resize(plainText.size() - padding_len);
    return plainText;
}