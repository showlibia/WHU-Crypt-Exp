#include "AES.h"
#include <wmmintrin.h>

std::vector<uint8_t> AESNI::encrypt(const std::vector<uint8_t> &plainText,
                                    const std::vector<uint8_t> &key) {
  if (key.size() != 16) {
    throw std::invalid_argument("Key size must be 16 bytes for AES-128");
  }

  __m128i key_schedule = _mm_loadu_si128((__m128i *)key.data());
  __m128i block;

  std::vector<uint8_t> paddedText = plainText;
  size_t padding_len = 16 - (plainText.size() % 16);
  paddedText.insert(paddedText.end(), padding_len, padding_len);

  std::vector<uint8_t> cipherText(paddedText.size());

  for (size_t i = 0; i < paddedText.size(); i += 16) {
    block = _mm_loadu_si128((__m128i *)&paddedText[i]);

    block = _mm_xor_si128(block, key_schedule); // 初始轮密钥加
    for (int round = 1; round < 10; ++round) {
      block = _mm_aesenc_si128(block, key_schedule);
    }
    block = _mm_aesenclast_si128(block, key_schedule);

    _mm_storeu_si128((__m128i *)&cipherText[i], block);
  }

  return cipherText;
}

std::vector<uint8_t> AESNI::decrypt(const std::vector<uint8_t> &cipherText,
                                    const std::vector<uint8_t> &key) {
  if (key.size() != 16) {
    throw std::invalid_argument("Key size must be 16 bytes for AES-128");
  }

  if (cipherText.size() % 16 != 0) {
    throw std::invalid_argument(
        "Cipher text size must be a multiple of 16 bytes");
  }

  __m128i key_schedule = _mm_loadu_si128((__m128i *)key.data());
  __m128i block;

  std::vector<uint8_t> plainText(cipherText.size());

  for (size_t i = 0; i < cipherText.size(); i += 16) {
    block = _mm_loadu_si128((__m128i *)&cipherText[i]);

    block = _mm_xor_si128(block, key_schedule); // 初始轮密钥加
    for (int round = 1; round < 10; ++round) {
      block = _mm_aesdec_si128(block, key_schedule);
    }
    block = _mm_aesdeclast_si128(block, key_schedule);

    _mm_storeu_si128((__m128i *)&plainText[i], block);
  }

  size_t padding_len = plainText.back();
  plainText.resize(plainText.size() - padding_len);

  return plainText;
}
