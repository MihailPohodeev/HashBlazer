#ifndef HASH_BLAZER_SHA512_HASHER_HXX
#define HASH_BLAZER_SHA512_HASHER_HXX

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "base.hxx"

namespace HashBlazer {

class SHA512_Hasher {
 public:
  constexpr static size_t HASH_SIZE_BYTES = 64;

  SHA512_Hasher();

  void update(std::span<const uint8_t> data);

  std::vector<uint8_t> finish();

  void reset();

 private:
  constexpr static size_t PROCESS_BLOCK_SIZE_BYTES = 128;

  inline void process_block(const uint8_t* data);

  std::array<uint8_t, PROCESS_BLOCK_SIZE_BYTES> incompleteBlockBuffer_;
  size_t bufferOffset_;
  size_t sizeOfProcessedBlocks_;
  uint64_t h0_, h1_, h2_, h3_, h4_, h5_, h6_, h7_;
};

static_assert(isHasher<SHA512_Hasher>,
              "SHA512_Hasher doesn't satisfy isHasher<> concept.");

}  // namespace HashBlazer

#endif  // HASH_BLAZER_SHA512_HASHER_HXX
