#include <stdexcept>
#include <string>
#include <vector>
#include <wmmintrin.h>
#include <cstdint>


class AESNI {
public:
  static std::vector<uint8_t> encrypt(const std::vector<uint8_t> &plainText,
                                      const std::vector<uint8_t> &key);

  static std::vector<uint8_t> decrypt(const std::vector<uint8_t> &cipherText,
                                      const std::vector<uint8_t> &key);
};
