// sha224.cxx
#include "sha224.hxx"

#include <cstring>

namespace HashBlazer {

namespace {

inline uint32_t rotate_right(uint32_t word, int32_t n) {
  return (word >> n) | (word << (32 - n));
}

inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ ((~x) & z);
}

inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t big_sigma0(uint32_t x) {
  return rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22);
}

inline uint32_t big_sigma1(uint32_t x) {
  return rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25);
}

inline uint32_t small_sigma0(uint32_t x) {
  return rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3);
}

inline uint32_t small_sigma1(uint32_t x) {
  return rotate_right(x, 17) ^ rotate_right(x, 19) ^ (x >> 10);
}

constexpr uint32_t K_ARRAY[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

}  // namespace

SHA224_Hasher::SHA224_Hasher() { reset(); }

void SHA224_Hasher::reset() {
  h0_ = 0xc1059ed8;
  h1_ = 0x367cd507;
  h2_ = 0x3070dd17;
  h3_ = 0xf70e5939;
  h4_ = 0xffc00b31;
  h5_ = 0x68581511;
  h6_ = 0x64f98fa7;
  h7_ = 0xbefa4fa4;

  bufferOffset_ = 0;
  sizeOfProcessedBlocks_ = 0;
}

void SHA224_Hasher::update(std::span<const uint8_t> data) {
  size_t dataSize = data.size();
  size_t offset = 0;

  if (bufferOffset_ != 0) {
    size_t additionalSize =
        std::min(dataSize, PROCESS_BLOCK_SIZE_BYTES - bufferOffset_);
    std::memcpy(incompleteBlockBuffer_.data() + bufferOffset_, data.data(),
                additionalSize);
    bufferOffset_ += additionalSize;

    if (bufferOffset_ == PROCESS_BLOCK_SIZE_BYTES) {
      process_block(incompleteBlockBuffer_.data());
      bufferOffset_ = 0;
    }

    dataSize -= additionalSize;
    offset = additionalSize;
  }

  size_t fullBlocksCount = dataSize / PROCESS_BLOCK_SIZE_BYTES;
  for (size_t i = 0; i < fullBlocksCount; ++i) {
    process_block(&data[offset + PROCESS_BLOCK_SIZE_BYTES * i]);
    sizeOfProcessedBlocks_++;
  }

  size_t remainingBytes = dataSize % PROCESS_BLOCK_SIZE_BYTES;
  if (remainingBytes > 0) {
    std::memcpy(incompleteBlockBuffer_.data(),
                &data[offset + PROCESS_BLOCK_SIZE_BYTES * fullBlocksCount],
                remainingBytes);
    bufferOffset_ = remainingBytes;
  }
}

std::vector<uint8_t> SHA224_Hasher::finish() {
  uint64_t totalBits =
      (sizeOfProcessedBlocks_ * PROCESS_BLOCK_SIZE_BYTES + bufferOffset_) * 8;

  incompleteBlockBuffer_[bufferOffset_++] = 0x80;

  size_t remainingSpace = PROCESS_BLOCK_SIZE_BYTES - bufferOffset_;

  if (remainingSpace < 8) {
    while (bufferOffset_ < PROCESS_BLOCK_SIZE_BYTES) {
      incompleteBlockBuffer_[bufferOffset_++] = 0;
    }
    process_block(incompleteBlockBuffer_.data());
    sizeOfProcessedBlocks_++;
    bufferOffset_ = 0;

    while (bufferOffset_ < PROCESS_BLOCK_SIZE_BYTES - 8) {
      incompleteBlockBuffer_[bufferOffset_++] = 0;
    }
  } else {
    while (bufferOffset_ < PROCESS_BLOCK_SIZE_BYTES - 8) {
      incompleteBlockBuffer_[bufferOffset_++] = 0;
    }
  }

  for (int i = 7; i >= 0; --i) {
    incompleteBlockBuffer_[bufferOffset_++] =
        static_cast<uint8_t>(totalBits >> (i * 8));
  }

  process_block(incompleteBlockBuffer_.data());
  sizeOfProcessedBlocks_++;

  std::vector<uint8_t> result(HASH_SIZE_BYTES);
  for (int i = 0; i < 4; ++i) {
    result[i] = (h0_ >> (24 - i * 8)) & 0xFF;
    result[i + 4] = (h1_ >> (24 - i * 8)) & 0xFF;
    result[i + 8] = (h2_ >> (24 - i * 8)) & 0xFF;
    result[i + 12] = (h3_ >> (24 - i * 8)) & 0xFF;
    result[i + 16] = (h4_ >> (24 - i * 8)) & 0xFF;
    result[i + 20] = (h5_ >> (24 - i * 8)) & 0xFF;
    result[i + 24] = (h6_ >> (24 - i * 8)) & 0xFF;
  }

  reset();
  return result;
}

void SHA224_Hasher::process_block(
    const uint8_t* data) {
  uint32_t w[64];

  for (int i = 0; i < 16; ++i) {
    w[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) |
           (data[i * 4 + 2] << 8) | data[i * 4 + 3];
  }

  for (int i = 16; i < 64; ++i) {
    w[i] =
        small_sigma1(w[i - 2]) + w[i - 7] + small_sigma0(w[i - 15]) + w[i - 16];
  }

  uint32_t a = h0_;
  uint32_t b = h1_;
  uint32_t c = h2_;
  uint32_t d = h3_;
  uint32_t e = h4_;
  uint32_t f = h5_;
  uint32_t g = h6_;
  uint32_t h = h7_;

  for (int t = 0; t < 64; ++t) {
    uint32_t temp1 = h + big_sigma1(e) + ch(e, f, g) + K_ARRAY[t] + w[t];
    uint32_t temp2 = big_sigma0(a) + maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  h0_ += a;
  h1_ += b;
  h2_ += c;
  h3_ += d;
  h4_ += e;
  h5_ += f;
  h6_ += g;
  h7_ += h;
}

}  // namespace HashBlazer
