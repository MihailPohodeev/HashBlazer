#include <gtest/gtest.h>

#include <string_view>

#include "base.hxx"
#include "sha512.hxx"

namespace HashBlazer::Test {
TEST(SHA512Test, BasicTest) {
  SHA512_Hasher hasher{};

  const std::string_view hello_string = "hello";
  auto hello_span = std::span<const uint8_t>{
      reinterpret_cast<const uint8_t*>(hello_string.data()),
      hello_string.size()};
  hasher.update(hello_span);
  auto hello_hash = hasher.finish();
  auto hash_str = hex_encode(hello_hash, false);

  EXPECT_EQ(hash_str,
            "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca723"
            "23c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043");

  const std::string_view empty_string = "";
  auto empty_span = std::span<const uint8_t>{
      reinterpret_cast<const uint8_t*>(empty_string.data()),
      empty_string.size()};
  hasher.update(empty_span);
  auto empty_hash = hasher.finish();
  hash_str = hex_encode(empty_hash, false);

  EXPECT_EQ(hash_str,
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47"
            "d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

  const std::string_view nums_string = "1234567890";
  auto nums_span = std::span<const uint8_t>{
      reinterpret_cast<const uint8_t*>(nums_string.data()), nums_string.size()};
  hasher.update(nums_span);
  auto nums_hash = hasher.finish();
  hash_str = hex_encode(nums_hash, false);

  EXPECT_EQ(hash_str,
            "12b03226a6d8be9c6e8cd5e55dc6c7920caaa39df14aab92d5e3ea9340d1c8a4d3"
            "d0b8e4314f1f6ef131ba4bf1ceb9186ab87c801af0d5c95b1befb8cedae2b9");
}
}  // namespace HashBlazer::Test
