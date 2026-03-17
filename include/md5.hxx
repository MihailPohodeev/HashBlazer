#ifndef HASH_BLAZER_MD5_HASHER_HXX
#define HASH_BLAZER_MD5_HASHER_HXX

#include <array>
#include <byte>
#include <cstdint>
#include <span>
#include <vector>

namespace HashBlazer {
class MD5_Hasher {
   public:
    constexpr static size_t HASH_SIZE_BYTES = 16;
    constexpr static size_t PROCESS_BLOCK_SIZE_BYTES = 64;

    MD5_Hasher();

    void update(std::span<const std::byte> data);

    std::vector<std::byte> finish();

    void reset();

   private:
    std::array<std::byte, PROCESS_BLOCK_SIZE_BYTES> currentProcessBlock_;
    size_t currentProcessBlockOffset_;

    uint32_t A_, B_, C_, D_;
};
}  // namespace HashBlazer

#endif
