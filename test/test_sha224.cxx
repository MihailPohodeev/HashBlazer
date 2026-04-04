#include <gtest/gtest.h>

#include <string_view>

#include "base.hxx"
#include "sha224.hxx"

namespace HashBlazer::Test {
TEST(SHA224Test, BasicTest) {
  SHA224_Hasher hasher{};

  const std::string_view hello_string = "hello";
  auto hello_span = std::span<const uint8_t>{
      reinterpret_cast<const uint8_t*>(hello_string.data()),
      hello_string.size()};
  hasher.update(hello_span);
  auto hello_hash = hasher.finish();
  auto hash_str = hex_encode(hello_hash, false);

  EXPECT_EQ(hash_str,
            "ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193");

  const std::string_view empty_string = "";
  auto empty_span = std::span<const uint8_t>{
      reinterpret_cast<const uint8_t*>(empty_string.data()),
      empty_string.size()};
  hasher.update(empty_span);
  auto empty_hash = hasher.finish();
  hash_str = hex_encode(empty_hash, false);

  EXPECT_EQ(hash_str,
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");

  const std::string_view nums_string = "1234567890";
  auto nums_span = std::span<const uint8_t>{
      reinterpret_cast<const uint8_t*>(nums_string.data()), nums_string.size()};
  hasher.update(nums_span);
  auto nums_hash = hasher.finish();
  hash_str = hex_encode(nums_hash, false);

  EXPECT_EQ(hash_str,
            "b564e8a5cf20a254eb34e1ae98c3d957c351ce854491ccbeaeb220ea");
}
}  // namespace HashBlazer::Test
