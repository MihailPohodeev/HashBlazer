#ifndef HASH_BLAZER_BASE_HXX
#define HASH_BLAZER_BASE_HXX

#include <cstdint>
#include <span>
#include <string>

namespace HashBlazer {
std::string hex_encode(std::span<const uint8_t> data, bool uppercase = true);
}

#endif  // HASH_BLAZER_BASE_HXX
