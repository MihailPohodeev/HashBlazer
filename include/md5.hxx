#ifndef HASH_BLAZER_MD5_HASHER_HXX
#define HASH_BLAZER_MD5_HASHER_HXX

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "base.hxx"

namespace HashBlazer {
class MD5_Hasher {
 public:
  constexpr static size_t HASH_SIZE_BYTES = 16;

  MD5_Hasher();

  void update(std::span<const uint8_t> data);

  std::vector<uint8_t> finish();

  void reset();

 private:
  constexpr static size_t PROCESS_BLOCK_SIZE_BYTES = 64;

  inline void process_block(const uint8_t* data);

  std::array<uint8_t, PROCESS_BLOCK_SIZE_BYTES> incompleteBlockBuffer_;
  size_t bufferOffset_;
  size_t sizeOfProcessedBlocks_;
  uint32_t A_, B_, C_, D_;
};

static_assert(isHasher<MD5_Hasher>,
              "MD5_Hasher doesn't satisfy isHasher<> concept.");

}  // namespace HashBlazer

#endif
