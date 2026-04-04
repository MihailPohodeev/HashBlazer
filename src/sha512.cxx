#include "sha512.hxx"

#include <algorithm>
#include <bit>
#include <cstring>

namespace HashBlazer {

namespace {
inline uint64_t rotate_right(uint64_t word, int32_t n) {
  return (word >> n) | (word << (64 - n));
}

inline uint64_t sigma0(uint64_t x) {
  return rotate_right(x, 28) ^ rotate_right(x, 34) ^ rotate_right(x, 39);
}

inline uint64_t sigma1(uint64_t x) {
  return rotate_right(x, 14) ^ rotate_right(x, 18) ^ rotate_right(x, 41);
}

inline uint64_t gamma0(uint64_t x) {
  return rotate_right(x, 1) ^ rotate_right(x, 8) ^ (x >> 7);
}

inline uint64_t gamma1(uint64_t x) {
  return rotate_right(x, 19) ^ rotate_right(x, 61) ^ (x >> 6);
}

inline uint64_t Ch(uint64_t x, uint64_t y, uint64_t z) {
  return (x & y) ^ ((~x) & z);
}

inline uint64_t Maj(uint64_t x, uint64_t y, uint64_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

constexpr uint64_t K_SHA512[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
    0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
    0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
    0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
    0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
    0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
    0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817};
}  // namespace

SHA512_Hasher::SHA512_Hasher() { reset(); }

void SHA512_Hasher::reset() {
  h0_ = 0x6a09e667f3bcc908;
  h1_ = 0xbb67ae8584caa73b;
  h2_ = 0x3c6ef372fe94f82b;
  h3_ = 0xa54ff53a5f1d36f1;
  h4_ = 0x510e527fade682d1;
  h5_ = 0x9b05688c2b3e6c1f;
  h6_ = 0x1f83d9abfb41bd6b;
  h7_ = 0x5be0cd19137e2179;

  bufferOffset_ = 0;
  sizeOfProcessedBlocks_ = 0;
}

void SHA512_Hasher::update(std::span<const uint8_t> data) {
  size_t dataSize = data.size();
  size_t offset = 0;

  if (bufferOffset_ > 0) {
    size_t canCopy =
        std::min(dataSize, PROCESS_BLOCK_SIZE_BYTES - bufferOffset_);
    std::memcpy(incompleteBlockBuffer_.data() + bufferOffset_, data.data(),
                canCopy);
    bufferOffset_ += canCopy;

    if (bufferOffset_ == PROCESS_BLOCK_SIZE_BYTES) {
      process_block(incompleteBlockBuffer_.data());
      bufferOffset_ = 0;
    }
    dataSize -= canCopy;
    offset += canCopy;
  }

  while (dataSize >= PROCESS_BLOCK_SIZE_BYTES) {
    process_block(data.data() + offset);
    offset += PROCESS_BLOCK_SIZE_BYTES;
    dataSize -= PROCESS_BLOCK_SIZE_BYTES;
  }

  if (dataSize > 0) {
    std::memcpy(incompleteBlockBuffer_.data(), data.data() + offset, dataSize);
    bufferOffset_ = dataSize;
  }
}

std::vector<uint8_t> SHA512_Hasher::finish() {
  uint64_t totalBits =
      (sizeOfProcessedBlocks_ * PROCESS_BLOCK_SIZE_BYTES + bufferOffset_) * 8;

  incompleteBlockBuffer_[bufferOffset_++] = 0x80;

  if (bufferOffset_ > (PROCESS_BLOCK_SIZE_BYTES - 16)) {
    std::memset(incompleteBlockBuffer_.data() + bufferOffset_, 0,
                PROCESS_BLOCK_SIZE_BYTES - bufferOffset_);
    process_block(incompleteBlockBuffer_.data());
    bufferOffset_ = 0;
  }

  std::memset(incompleteBlockBuffer_.data() + bufferOffset_, 0,
              (PROCESS_BLOCK_SIZE_BYTES - 16) - bufferOffset_);
  bufferOffset_ = PROCESS_BLOCK_SIZE_BYTES - 16;

  std::memset(incompleteBlockBuffer_.data() + bufferOffset_, 0, 8);
  bufferOffset_ += 8;

  for (int i = 7; i >= 0; --i) {
    incompleteBlockBuffer_[bufferOffset_++] =
        static_cast<uint8_t>(totalBits >> (i * 8));
  }

  process_block(incompleteBlockBuffer_.data());

  std::vector<uint8_t> result(HASH_SIZE_BYTES);
  uint64_t* h_vars[8] = {&h0_, &h1_, &h2_, &h3_, &h4_, &h5_, &h6_, &h7_};

  for (int i = 0; i < 8; ++i) {
    for (int j = 0; j < 8; ++j) {
      result[i * 8 + j] =
          static_cast<uint8_t>((*h_vars[i] >> (56 - j * 8)) & 0xFF);
    }
  }

  reset();
  return result;
}

inline uint64_t load_be64(const uint8_t* p) {
  return (static_cast<uint64_t>(p[0]) << 56) |
         (static_cast<uint64_t>(p[1]) << 48) |
         (static_cast<uint64_t>(p[2]) << 40) |
         (static_cast<uint64_t>(p[3]) << 32) |
         (static_cast<uint64_t>(p[4]) << 24) |
         (static_cast<uint64_t>(p[5]) << 16) |
         (static_cast<uint64_t>(p[6]) << 8) | (static_cast<uint64_t>(p[7]));
}

void SHA512_Hasher::process_block(const uint8_t* data) {
  uint64_t w[80];

  for (int i = 0; i < 16; ++i) w[i] = load_be64(data + (i * 8));

  for (int i = 16; i < 80; ++i)
    w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];

  uint64_t a = h0_, b = h1_, c = h2_, d = h3_, e = h4_, f = h5_, g = h6_,
           h = h7_;

#define SHA512_STEP(a, b, c, d, e, f, g, h, t)                        \
  {                                                                   \
    uint64_t tmp1 = h + sigma1(e) + Ch(e, f, g) + K_SHA512[t] + w[t]; \
    uint64_t tmp2 = sigma0(a) + Maj(a, b, c);                         \
    d += tmp1;                                                        \
    h = tmp1 + tmp2;                                                  \
  }

  for (int t = 0; t < 80; t += 8) {
    SHA512_STEP(a, b, c, d, e, f, g, h, t + 0);
    SHA512_STEP(h, a, b, c, d, e, f, g, t + 1);
    SHA512_STEP(g, h, a, b, c, d, e, f, t + 2);
    SHA512_STEP(f, g, h, a, b, c, d, e, t + 3);
    SHA512_STEP(e, f, g, h, a, b, c, d, t + 4);
    SHA512_STEP(d, e, f, g, h, a, b, c, t + 5);
    SHA512_STEP(c, d, e, f, g, h, a, b, t + 6);
    SHA512_STEP(b, c, d, e, f, g, h, a, t + 7);
  }

  h0_ += a;
  h1_ += b;
  h2_ += c;
  h3_ += d;
  h4_ += e;
  h5_ += f;
  h6_ += g;
  h7_ += h;

  sizeOfProcessedBlocks_++;
}

}  // namespace HashBlazer
