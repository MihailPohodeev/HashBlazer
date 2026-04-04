#include <gtest/gtest.h>

#include <string_view>

#include "base.hxx"
#include "sha384.hxx"

namespace HashBlazer::Test {
TEST(SHA384Test, BasicTest) {
  SHA384_Hasher hasher{};

  const std::string_view hello_string = "hello";
  auto hello_span = std::span<const uint8_t>{
      reinterpret_cast<const uint8_t*>(hello_string.data()),
      hello_string.size()};
  hasher.update(hello_span);
  auto hello_hash = hasher.finish();
  auto hash_str = hex_encode(hello_hash, false);

  EXPECT_EQ(hash_str,
            "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa9012"
            "5a3c79f90397bdf5f6a13de828684f");

  const std::string_view empty_string = "";
  auto empty_span = std::span<const uint8_t>{
      reinterpret_cast<const uint8_t*>(empty_string.data()),
      empty_string.size()};
  hasher.update(empty_span);
  auto empty_hash = hasher.finish();
  hash_str = hex_encode(empty_hash, false);

  EXPECT_EQ(hash_str,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da27"
            "4edebfe76f65fbd51ad2f14898b95b");

  const std::string_view nums_string = "1234567890";
  auto nums_span = std::span<const uint8_t>{
      reinterpret_cast<const uint8_t*>(nums_string.data()), nums_string.size()};
  hasher.update(nums_span);
  auto nums_hash = hasher.finish();
  hash_str = hex_encode(nums_hash, false);

  EXPECT_EQ(hash_str,
            "ed845f8b4f2a6d5da86a3bec90352d916d6a66e3420d720e16439adf238f129182"
            "c8c64fc4ec8c1e6506bc2b4888baf9");
}
}  // namespace HashBlazer::Test
