// sha1.cxx
#include "sha1.hxx"

#include <concepts>
#include <cstring>

namespace HashBlazer {

namespace {

inline uint32_t rotate_left(uint32_t word, int32_t n) {
  return (word << n) | (word >> (32 - n));
}

inline uint32_t f1(uint32_t b, uint32_t c, uint32_t d) {
  return (b & c) | ((~b) & d);
}

inline uint32_t f2(uint32_t b, uint32_t c, uint32_t d) { return b ^ c ^ d; }

inline uint32_t f3(uint32_t b, uint32_t c, uint32_t d) {
  return (b & c) | (b & d) | (c & d);
}

inline uint32_t f(int t, uint32_t b, uint32_t c, uint32_t d) {
  if (t < 20) return f1(b, c, d);
  if (t < 40) return f2(b, c, d);
  if (t < 60) return f3(b, c, d);
  return f2(b, c, d);  // 60-79
}

inline uint32_t k(int t) {
  if (t < 20) return 0x5A827999;
  if (t < 40) return 0x6ED9EBA1;
  if (t < 60) return 0x8F1BBCDC;
  return 0xCA62C1D6;
}

#define SHA1_STEP(t, a, b, c, d, e, w)                                \
  do {                                                                \
    uint32_t temp = rotate_left(a, 5) + f(t, b, c, d) + e + w + k(t); \
    e = d;                                                            \
    d = c;                                                            \
    c = rotate_left(b, 30);                                           \
    b = a;                                                            \
    a = temp;                                                         \
  } while (0)

}  // namespace

SHA1_Hasher::SHA1_Hasher() { reset(); }

void SHA1_Hasher::reset() {
  h0_ = 0x67452301;
  h1_ = 0xEFCDAB89;
  h2_ = 0x98BADCFE;
  h3_ = 0x10325476;
  h4_ = 0xC3D2E1F0;

  bufferOffset_ = 0;
  sizeOfProcessedBlocks_ = 0;
}

void SHA1_Hasher::update(std::span<const uint8_t> data) {
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
  }

  size_t remainingBytes = dataSize % PROCESS_BLOCK_SIZE_BYTES;
  if (remainingBytes > 0) {
    std::memcpy(incompleteBlockBuffer_.data(),
                &data[offset + PROCESS_BLOCK_SIZE_BYTES * fullBlocksCount],
                remainingBytes);
    bufferOffset_ = remainingBytes;
  }
}

std::vector<uint8_t> SHA1_Hasher::finish() {
  uint64_t totalBits =
      (sizeOfProcessedBlocks_ * PROCESS_BLOCK_SIZE_BYTES + bufferOffset_) * 8;

  incompleteBlockBuffer_[bufferOffset_++] = 0x80;

  size_t remainingSpace = PROCESS_BLOCK_SIZE_BYTES - bufferOffset_;

  if (remainingSpace < 8) {
    while (bufferOffset_ < PROCESS_BLOCK_SIZE_BYTES) {
      incompleteBlockBuffer_[bufferOffset_++] = 0;
    }
    process_block(incompleteBlockBuffer_.data());
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

  std::vector<uint8_t> result(HASH_SIZE_BYTES);
  for (int i = 0; i < 4; ++i) {
    result[i] = (h0_ >> (24 - i * 8)) & 0xFF;
    result[i + 4] = (h1_ >> (24 - i * 8)) & 0xFF;
    result[i + 8] = (h2_ >> (24 - i * 8)) & 0xFF;
    result[i + 12] = (h3_ >> (24 - i * 8)) & 0xFF;
    result[i + 16] = (h4_ >> (24 - i * 8)) & 0xFF;
  }

  reset();
  return result;
}

namespace {

inline uint32_t load_be32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | (static_cast<uint32_t>(p[3]));
}

// Те самые раунды SHA-1 без if-условий
#define SHA1_R0(a, b, c, d, e, i)                                   \
  e += ((b & (c ^ d)) ^ d) + w[i] + 0x5A827999 + rotate_left(a, 5); \
  b = rotate_left(b, 30);
#define SHA1_R1(a, b, c, d, e, i)                                     \
  w[i] = rotate_left(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1); \
  e += ((b & (c ^ d)) ^ d) + w[i] + 0x5A827999 + rotate_left(a, 5);   \
  b = rotate_left(b, 30);
#define SHA1_R2(a, b, c, d, e, i)                                     \
  w[i] = rotate_left(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1); \
  e += (b ^ c ^ d) + w[i] + 0x6ED9EBA1 + rotate_left(a, 5);           \
  b = rotate_left(b, 30);
#define SHA1_R3(a, b, c, d, e, i)                                         \
  w[i] = rotate_left(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);     \
  e += (((b | c) & d) | (b & c)) + w[i] + 0x8F1BBCDC + rotate_left(a, 5); \
  b = rotate_left(b, 30);
#define SHA1_R4(a, b, c, d, e, i)                                     \
  w[i] = rotate_left(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1); \
  e += (b ^ c ^ d) + w[i] + 0xCA62C1D6 + rotate_left(a, 5);           \
  b = rotate_left(b, 30);

}  // namespace

void SHA1_Hasher::process_block(
    const uint8_t* data) {
  uint32_t w[80];
  uint32_t a = h0_, b = h1_, c = h2_, d = h3_, e = h4_;

  // 1. Загрузка первых 16 слов
  for (int i = 0; i < 16; ++i) {
    w[i] = load_be32(data + (i * 4));
  }

  // 2. Раунды 0-15 (используем уже загруженные w)
  SHA1_R0(a, b, c, d, e, 0);
  SHA1_R0(e, a, b, c, d, 1);
  SHA1_R0(d, e, a, b, c, 2);
  SHA1_R0(c, d, e, a, b, 3);
  SHA1_R0(b, c, d, e, a, 4);
  SHA1_R0(a, b, c, d, e, 5);
  SHA1_R0(e, a, b, c, d, 6);
  SHA1_R0(d, e, a, b, c, 7);
  SHA1_R0(c, d, e, a, b, 8);
  SHA1_R0(b, c, d, e, a, 9);
  SHA1_R0(a, b, c, d, e, 10);
  SHA1_R0(e, a, b, c, d, 11);
  SHA1_R0(d, e, a, b, c, 12);
  SHA1_R0(c, d, e, a, b, 13);
  SHA1_R0(b, c, d, e, a, 14);
  SHA1_R0(a, b, c, d, e, 15);

  // 3. Раунды 16-19 (начинаем расширять w на лету)
  SHA1_R1(e, a, b, c, d, 16);
  SHA1_R1(d, e, a, b, c, 17);
  SHA1_R1(c, d, e, a, b, 18);
  SHA1_R1(b, c, d, e, a, 19);

  // 4. Раунды 20-39
  for (int i = 20; i < 40; i += 5) {
    SHA1_R2(a, b, c, d, e, i);
    SHA1_R2(e, a, b, c, d, i + 1);
    SHA1_R2(d, e, a, b, c, i + 2);
    SHA1_R2(c, d, e, a, b, i + 3);
    SHA1_R2(b, c, d, e, a, i + 4);
  }

  // 5. Раунды 40-59
  for (int i = 40; i < 60; i += 5) {
    SHA1_R3(a, b, c, d, e, i);
    SHA1_R3(e, a, b, c, d, i + 1);
    SHA1_R3(d, e, a, b, c, i + 2);
    SHA1_R3(c, d, e, a, b, i + 3);
    SHA1_R3(b, c, d, e, a, i + 4);
  }

  // 6. Раунды 60-79
  for (int i = 60; i < 80; i += 5) {
    SHA1_R4(a, b, c, d, e, i);
    SHA1_R4(e, a, b, c, d, i + 1);
    SHA1_R4(d, e, a, b, c, i + 2);
    SHA1_R4(c, d, e, a, b, i + 3);
    SHA1_R4(b, c, d, e, a, i + 4);
  }

  h0_ += a;
  h1_ += b;
  h2_ += c;
  h3_ += d;
  h4_ += e;
  sizeOfProcessedBlocks_++;
}

}  // namespace HashBlazer
