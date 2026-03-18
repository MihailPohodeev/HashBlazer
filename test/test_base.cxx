#include <gtest/gtest.h>

#include <vector>

#include "base.hxx"

namespace HashBlazer::Test {
TEST(Base, hex_encoding) {
    std::vector<uint8_t> vec{0x00, 0x01, 0x02, 0x04, 0xFC, 0xFD, 0xFE, 0xFF};
    std::string hex = hex_encode(vec, true);

    EXPECT_EQ(hex, "00010204FCFDFEFF");

    vec = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
           0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    std::string hex_low = hex_encode(vec, false);
    std::string hex_up = hex_encode(vec, true);

    EXPECT_EQ(hex_low, "00112233445566778899aabbccddeeff");
    EXPECT_EQ(hex_up, "00112233445566778899AABBCCDDEEFF");

    vec = {};
    hex = hex_encode(vec);

    EXPECT_EQ(hex, "");
}
}  // namespace HashBlazer::Test
