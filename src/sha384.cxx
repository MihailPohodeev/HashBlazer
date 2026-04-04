// sha384.cxx
#include "sha384.hxx"

#include <cstring>

namespace HashBlazer {

namespace {

inline uint64_t rotate_right(uint64_t word, int32_t n) {
  return (word >> n) | (word << (64 - n));
}

inline uint64_t ch(uint64_t x, uint64_t y, uint64_t z) {
  return (x & y) ^ ((~x) & z);
}

inline uint64_t maj(uint64_t x, uint64_t y, uint64_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

inline uint64_t big_sigma0(uint64_t x) {
  return rotate_right(x, 28) ^ rotate_right(x, 34) ^ rotate_right(x, 39);
}

inline uint64_t big_sigma1(uint64_t x) {
  return rotate_right(x, 14) ^ rotate_right(x, 18) ^ rotate_right(x, 41);
}

inline uint64_t small_sigma0(uint64_t x) {
  return rotate_right(x, 1) ^ rotate_right(x, 8) ^ (x >> 7);
}

inline uint64_t small_sigma1(uint64_t x) {
  return rotate_right(x, 19) ^ rotate_right(x, 61) ^ (x >> 6);
}

constexpr uint64_t K_ARRAY[80] = {
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

SHA384_Hasher::SHA384_Hasher() { reset(); }

void SHA384_Hasher::reset() {
  h0_ = 0xcbbb9d5dc1059ed8;
  h1_ = 0x629a292a367cd507;
  h2_ = 0x9159015a3070dd17;
  h3_ = 0x152fecd8f70e5939;
  h4_ = 0x67332667ffc00b31;
  h5_ = 0x8eb44a8768581511;
  h6_ = 0xdb0c2e0d64f98fa7;
  h7_ = 0x47b5481dbefa4fa4;

  bufferOffset_ = 0;
  sizeOfProcessedBlocks_ = 0;
}

void SHA384_Hasher::update(std::span<const uint8_t> data) {
  size_t dataSize = data.size();
  size_t offset = 0;

  // 1. Дозаполнение существующего буфера
  if (bufferOffset_ > 0) {
    size_t canCopy =
        std::min(dataSize, PROCESS_BLOCK_SIZE_BYTES - bufferOffset_);
    std::memcpy(incompleteBlockBuffer_.data() + bufferOffset_, data.data(),
                canCopy);
    bufferOffset_ += canCopy;

    if (bufferOffset_ == PROCESS_BLOCK_SIZE_BYTES) {
      process_block(incompleteBlockBuffer_.data());
      sizeOfProcessedBlocks_++;
      bufferOffset_ = 0;
    }
    dataSize -= canCopy;
    offset += canCopy;
  }

  // 2. Обработка полных блоков напрямую из входных данных
  while (dataSize >= PROCESS_BLOCK_SIZE_BYTES) {
    process_block(data.data() + offset);
    sizeOfProcessedBlocks_++;
    offset += PROCESS_BLOCK_SIZE_BYTES;
    dataSize -= PROCESS_BLOCK_SIZE_BYTES;
  }

  // 3. Сохранение остатка
  if (dataSize > 0) {
    std::memcpy(incompleteBlockBuffer_.data(), data.data() + offset, dataSize);
    bufferOffset_ = dataSize;
  }
}

std::vector<uint8_t> SHA384_Hasher::finish() {
  // Рассчитываем общую длину в битах
  // Внимание: для полной корректности SHA-512/384 использует 128 бит для длины.
  // Здесь мы используем 64 бита, чего хватит для данных до ~2 эксабайт.
  uint64_t totalBits =
      (sizeOfProcessedBlocks_ * PROCESS_BLOCK_SIZE_BYTES + bufferOffset_) * 8;

  // Шаг 1: Добавляем бит '1' (байт 0x80)
  incompleteBlockBuffer_[bufferOffset_++] = 0x80;

  // Шаг 2: Проверяем, влезет ли 16 байт длины в текущий блок
  // Нам нужно: [данные] + [0x80] + [нули] + [16 байт длины] = 128 байт
  if (bufferOffset_ > (PROCESS_BLOCK_SIZE_BYTES - 16)) {
    while (bufferOffset_ < PROCESS_BLOCK_SIZE_BYTES) {
      incompleteBlockBuffer_[bufferOffset_++] = 0;
    }
    process_block(incompleteBlockBuffer_.data());
    bufferOffset_ = 0;
  }

  // Заполняем нулями до позиции записи длины (последние 16 байт блока)
  while (bufferOffset_ < (PROCESS_BLOCK_SIZE_BYTES - 16)) {
    incompleteBlockBuffer_[bufferOffset_++] = 0;
  }

  // Шаг 3: Записываем длину (128 бит). Первые 8 байт будут 0 (если сообщение <
  // 2^64 бит)
  for (int i = 0; i < 8; ++i) incompleteBlockBuffer_[bufferOffset_++] = 0;

  // Записываем младшие 64 бита длины (Big Endian)
  for (int i = 7; i >= 0; --i) {
    incompleteBlockBuffer_[bufferOffset_++] =
        static_cast<uint8_t>(totalBits >> (i * 8));
  }

  process_block(incompleteBlockBuffer_.data());

  // Шаг 4: Сборка результата (48 байт для SHA-384)
  std::vector<uint8_t> result(HASH_SIZE_BYTES);
  auto h_ptrs = {h0_, h1_, h2_,
                 h3_, h4_, h5_};  // h6_ и h7_ в SHA-384 не экспортируются

  size_t outIdx = 0;
  for (uint64_t val : h_ptrs) {
    for (int i = 7; i >= 0; --i) {
      result[outIdx++] = static_cast<uint8_t>(val >> (i * 8));
    }
  }

  reset();
  return result;
}

__attribute__((always_inline)) void SHA384_Hasher::process_block(
    const uint8_t* data) {
  uint64_t w[80];

  for (int i = 0; i < 16; ++i) {
    w[i] = (static_cast<uint64_t>(data[i * 8]) << 56) |
           (static_cast<uint64_t>(data[i * 8 + 1]) << 48) |
           (static_cast<uint64_t>(data[i * 8 + 2]) << 40) |
           (static_cast<uint64_t>(data[i * 8 + 3]) << 32) |
           (static_cast<uint64_t>(data[i * 8 + 4]) << 24) |
           (static_cast<uint64_t>(data[i * 8 + 5]) << 16) |
           (static_cast<uint64_t>(data[i * 8 + 6]) << 8) |
           static_cast<uint64_t>(data[i * 8 + 7]);
  }

  for (int i = 16; i < 80; ++i) {
    w[i] =
        small_sigma1(w[i - 2]) + w[i - 7] + small_sigma0(w[i - 15]) + w[i - 16];
  }

  uint64_t a = h0_;
  uint64_t b = h1_;
  uint64_t c = h2_;
  uint64_t d = h3_;
  uint64_t e = h4_;
  uint64_t f = h5_;
  uint64_t g = h6_;
  uint64_t h = h7_;

  for (int t = 0; t < 80; ++t) {
    uint64_t temp1 = h + big_sigma1(e) + ch(e, f, g) + K_ARRAY[t] + w[t];
    uint64_t temp2 = big_sigma0(a) + maj(a, b, c);
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
