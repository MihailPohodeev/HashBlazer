#include <gtest/gtest.h>

#include <string_view>

#include "base.hxx"
#include "md5.hxx"

namespace HashBlazer::Test {
TEST(MD5Test, BasicTest) {
    MD5_Hasher hasher{};

    const std::string_view hello_string = "hello";
    auto hello_span = std::span<const uint8_t>{
        reinterpret_cast<const uint8_t*>(hello_string.data()),
        hello_string.size()};
    hasher.update(hello_span);
    auto hello_hash = hasher.finish();
    auto hash_str = hex_encode(hello_hash, false);

    EXPECT_EQ(hash_str, "5d41402abc4b2a76b9719d911017c592");

    const std::string_view empty_string = "";
    auto empty_span = std::span<const uint8_t>{
        reinterpret_cast<const uint8_t*>(empty_string.data()),
        empty_string.size()};
    hasher.update(empty_span);
    auto empty_hash = hasher.finish();
    hash_str = hex_encode(empty_hash, false);

    EXPECT_EQ(hash_str, "d41d8cd98f00b204e9800998ecf8427e");
}
}  // namespace HashBlazer::Test
