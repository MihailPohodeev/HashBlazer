#include <gtest/gtest.h>

#include <string_view>

#include "base.hxx"
#include "sha1.hxx"

namespace HashBlazer::Test {
TEST(SHA1Test, BasicTest) {
  SHA1_Hasher hasher{};

  const std::string_view hello_string = "hello";
  auto hello_span = std::span<const uint8_t>{
      reinterpret_cast<const uint8_t*>(hello_string.data()),
      hello_string.size()};
  hasher.update(hello_span);
  auto hello_hash = hasher.finish();
  auto hash_str = hex_encode(hello_hash, false);

  EXPECT_EQ(hash_str, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");

  const std::string_view empty_string = "";
  auto empty_span = std::span<const uint8_t>{
      reinterpret_cast<const uint8_t*>(empty_string.data()),
      empty_string.size()};
  hasher.update(empty_span);
  auto empty_hash = hasher.finish();
  hash_str = hex_encode(empty_hash, false);

  EXPECT_EQ(hash_str, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

  const std::string_view nums_string = "1234567890";
  auto nums_span = std::span<const uint8_t>{
      reinterpret_cast<const uint8_t*>(nums_string.data()), nums_string.size()};
  hasher.update(nums_span);
  auto nums_hash = hasher.finish();
  hash_str = hex_encode(nums_hash, false);

  EXPECT_EQ(hash_str, "01b307acba4f54f55aafc33bb06bbbf6ca803e9a");
}
}  // namespace HashBlazer::Test
