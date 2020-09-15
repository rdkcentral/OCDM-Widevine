#include "Policy.h"

#include <vector>
#include <iostream>

bool DecodeHexChar(char ch, unsigned char* digit) {
  if (ch >= '0' && ch <= '9') {
    *digit = ch - '0';
  } else {
    ch = tolower(ch);
    if ((ch >= 'a') && (ch <= 'f')) {
      *digit = ch - 'a' + 10;
    } else {
      return false;
    }
  }
  return true;
}

// converts an ascii hex string(2 bytes per digit) into a decimal byte string
std::vector<uint8_t> a2b_hex(const std::string& byte) {
  std::vector<uint8_t> array;
  unsigned int count = byte.size();
  if (count == 0 || (count % 2) != 0) {
    std::cerr << "Invalid input size " << count << " for string " << byte << std::endl;
    return array;
  }

  for (unsigned int i = 0; i < count / 2; ++i) {
    unsigned char msb = 0;  // most significant 4 bits
    unsigned char lsb = 0;  // least significant 4 bits
    if (!DecodeHexChar(byte[i * 2], &msb) ||
        !DecodeHexChar(byte[i * 2 + 1], &lsb)) {
      std::cerr << "Invalid hex value " << byte[i * 2] << " " << byte[i * 2 + 1] << " at index " << i << std::endl;
      return array;
    }
    array.push_back((msb << 4) | lsb);
  }
  return array;
}

std::string a2bs_hex(const std::string& byte) {
  std::vector<uint8_t> array = a2b_hex(byte);
  return std::string(array.begin(), array.end());
}

