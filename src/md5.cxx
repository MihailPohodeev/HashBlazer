#include "md5.hxx"

#include <concepts>
#include <cstring>

namespace HashBlazer {
namespace {
inline uint32_t F(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | (~x & z);
}

inline uint32_t G(uint32_t x, uint32_t y, uint32_t z) {
    return (x & z) | (~z & y);
}

inline uint32_t H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }

inline uint32_t I(uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); }

inline uint32_t rotate_left(uint32_t word, int32_t n) {
    return (word << n) | (word >> (32 - n));
}

constexpr uint32_t K_ARRAY[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

constexpr uint32_t MD5_S[] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

template <class Func>
    requires std::invocable<Func, uint32_t, uint32_t, uint32_t> &&
             std::same_as<
                 std::invoke_result_t<Func, uint32_t, uint32_t, uint32_t>,
                 uint32_t>
void round_step(Func func, uint32_t& a, uint32_t b, uint32_t c, uint32_t d,
                uint32_t M_i, int i) {
    a = b + rotate_left(a + func(b, c, d) + M_i + K_ARRAY[i], MD5_S[i]);
}

}  // namespace

MD5_Hasher::MD5_Hasher() { reset(); }

void MD5_Hasher::reset() {
    A_ = 0x67452301;
    B_ = 0xefcdab89;
    C_ = 0x98badcfe;
    D_ = 0x10325476;
    bufferOffset_ = 0;
    sizeOfProcessedBlocks_ = 0;
}

void MD5_Hasher::update(std::span<const uint8_t> data) {
    size_t dataSize = data.size();
    size_t offset = 0;
    if (bufferOffset_ != 0) {
        size_t additionalSize =
            std::min(dataSize, PROCESS_BLOCK_SIZE_BYTES - bufferOffset_);
        std::memcpy(incompleteBlockBuffer_.data() + bufferOffset_, data.data(),
                    additionalSize);
        bufferOffset_ = 0;
        dataSize -= additionalSize;
        offset = additionalSize;
        process_block(incompleteBlockBuffer_.data());
    }
    size_t fullBlocksCount = dataSize / PROCESS_BLOCK_SIZE_BYTES;
    size_t incompleteBytes = dataSize % PROCESS_BLOCK_SIZE_BYTES;
    std::memcpy(incompleteBlockBuffer_.data(),
                data.data() + data.size() - incompleteBytes, incompleteBytes);
    bufferOffset_ = incompleteBytes;

    for (size_t i = 0; i < fullBlocksCount; ++i)
        process_block(&data[offset + PROCESS_BLOCK_SIZE_BYTES * i]);
}

std::vector<uint8_t> MD5_Hasher::finish() {
    size_t sizeInBits =
        (sizeOfProcessedBlocks_ * PROCESS_BLOCK_SIZE_BYTES + bufferOffset_) * 8;
    incompleteBlockBuffer_[bufferOffset_++] = 0x80;
    size_t remainingSize = PROCESS_BLOCK_SIZE_BYTES - bufferOffset_;
    if (remainingSize < 8) {
        while (bufferOffset_ < PROCESS_BLOCK_SIZE_BYTES)
            incompleteBlockBuffer_[bufferOffset_++] = 0;

        process_block(incompleteBlockBuffer_.data());
        bufferOffset_ = 0;

        while (bufferOffset_ < PROCESS_BLOCK_SIZE_BYTES - 8)
            incompleteBlockBuffer_[bufferOffset_++] = 0;
    } else {
        while (bufferOffset_ < PROCESS_BLOCK_SIZE_BYTES - 8)
            incompleteBlockBuffer_[bufferOffset_++] = 0;
    }

    for (int i = 0; i < 8; ++i)
        incompleteBlockBuffer_[bufferOffset_++] =
            static_cast<uint8_t>(sizeInBits >> (i * 8));
    process_block(incompleteBlockBuffer_.data());

    std::vector<uint8_t> result(16);
    for (int i = 0; i < 4; ++i) {
        result[i] = (A_ >> (i * 8)) & 0xFF;
        result[i + 4] = (B_ >> (i * 8)) & 0xFF;
        result[i + 8] = (C_ >> (i * 8)) & 0xFF;
        result[i + 12] = (D_ >> (i * 8)) & 0xFF;
    }

    reset();
    return result;
}

void MD5_Hasher::process_block(const uint8_t* data) {
    uint32_t A = A_;
    uint32_t B = B_;
    uint32_t C = C_;
    uint32_t D = D_;

    uint32_t M[16];
    for (size_t i = 0; i < 16; ++i) {
        M[i] = static_cast<uint32_t>(data[i * 4]) |
               (static_cast<uint32_t>(data[i * 4 + 1]) << 8) |
               (static_cast<uint32_t>(data[i * 4 + 2]) << 16) |
               (static_cast<uint32_t>(data[i * 4 + 3]) << 24);
    }

    // round 1.
    round_step(F, A, B, C, D, M[0], 0);
    round_step(F, D, A, B, C, M[1], 1);
    round_step(F, C, D, A, B, M[2], 2);
    round_step(F, B, C, D, A, M[3], 3);

    round_step(F, A, B, C, D, M[4], 4);
    round_step(F, D, A, B, C, M[5], 5);
    round_step(F, C, D, A, B, M[6], 6);
    round_step(F, B, C, D, A, M[7], 7);

    round_step(F, A, B, C, D, M[8], 8);
    round_step(F, D, A, B, C, M[9], 9);
    round_step(F, C, D, A, B, M[10], 10);
    round_step(F, B, C, D, A, M[11], 11);

    round_step(F, A, B, C, D, M[12], 12);
    round_step(F, D, A, B, C, M[13], 13);
    round_step(F, C, D, A, B, M[14], 14);
    round_step(F, B, C, D, A, M[15], 15);

    // round 2.
    round_step(G, A, B, C, D, M[1], 16);
    round_step(G, D, A, B, C, M[6], 17);
    round_step(G, C, D, A, B, M[11], 18);
    round_step(G, B, C, D, A, M[0], 19);

    round_step(G, A, B, C, D, M[5], 20);
    round_step(G, D, A, B, C, M[10], 21);
    round_step(G, C, D, A, B, M[15], 22);
    round_step(G, B, C, D, A, M[4], 23);

    round_step(G, A, B, C, D, M[9], 24);
    round_step(G, D, A, B, C, M[14], 25);
    round_step(G, C, D, A, B, M[3], 26);
    round_step(G, B, C, D, A, M[8], 27);

    round_step(G, A, B, C, D, M[13], 28);
    round_step(G, D, A, B, C, M[2], 29);
    round_step(G, C, D, A, B, M[7], 30);
    round_step(G, B, C, D, A, M[12], 31);

    // round 3.
    round_step(H, A, B, C, D, M[5], 32);
    round_step(H, D, A, B, C, M[8], 33);
    round_step(H, C, D, A, B, M[11], 34);
    round_step(H, B, C, D, A, M[14], 35);

    round_step(H, A, B, C, D, M[1], 36);
    round_step(H, D, A, B, C, M[4], 37);
    round_step(H, C, D, A, B, M[7], 38);
    round_step(H, B, C, D, A, M[10], 39);

    round_step(H, A, B, C, D, M[13], 40);
    round_step(H, D, A, B, C, M[0], 41);
    round_step(H, C, D, A, B, M[3], 42);
    round_step(H, B, C, D, A, M[6], 43);

    round_step(H, A, B, C, D, M[9], 44);
    round_step(H, D, A, B, C, M[12], 45);
    round_step(H, C, D, A, B, M[15], 46);
    round_step(H, B, C, D, A, M[2], 47);

    // round 4.
    round_step(I, A, B, C, D, M[0], 48);
    round_step(I, D, A, B, C, M[7], 49);
    round_step(I, C, D, A, B, M[14], 50);
    round_step(I, B, C, D, A, M[5], 51);

    round_step(I, A, B, C, D, M[12], 52);
    round_step(I, D, A, B, C, M[3], 53);
    round_step(I, C, D, A, B, M[10], 54);
    round_step(I, B, C, D, A, M[1], 55);

    round_step(I, A, B, C, D, M[8], 56);
    round_step(I, D, A, B, C, M[15], 57);
    round_step(I, C, D, A, B, M[6], 58);
    round_step(I, B, C, D, A, M[13], 59);

    round_step(I, A, B, C, D, M[4], 60);
    round_step(I, D, A, B, C, M[11], 61);
    round_step(I, C, D, A, B, M[2], 62);
    round_step(I, B, C, D, A, M[9], 63);

    A_ += A;
    B_ += B;
    C_ += C;
    D_ += D;

    ++sizeOfProcessedBlocks_;
}

}  // namespace HashBlazer
