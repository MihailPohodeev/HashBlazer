#ifndef HASH_BLAZER_BASE_HXX
#define HASH_BLAZER_BASE_HXX

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace HashBlazer {

    template<class Hasher>
    concept isHasher = std::default_initializable<Hasher> && requires (Hasher hasher) {
        { hasher.update(std::span<const uint8_t>()) };
        { hasher.finish() } -> std::same_as<std::vector<uint8_t>>;
        { hasher.reset() };
    };

std::string hex_encode(std::span<const uint8_t> data, bool uppercase = true);
}

#endif  // HASH_BLAZER_BASE_HXX
