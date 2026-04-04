#include <gtest/gtest.h>

#include <string_view>

#include "base.hxx"
#include "sha256.hxx"

namespace HashBlazer::Test {
TEST(SHA256Test, BasicTest) {
  SHA256_Hasher hasher{};

  const std::string_view hello_string = "hello";
  auto hello_span = std::span<const uint8_t>{
      reinterpret_cast<const uint8_t*>(hello_string.data()),
      hello_string.size()};
  hasher.update(hello_span);
  auto hello_hash = hasher.finish();
  auto hash_str = hex_encode(hello_hash, false);

  EXPECT_EQ(hash_str,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");

  const std::string_view empty_string = "";
  auto empty_span = std::span<const uint8_t>{
      reinterpret_cast<const uint8_t*>(empty_string.data()),
      empty_string.size()};
  hasher.update(empty_span);
  auto empty_hash = hasher.finish();
  hash_str = hex_encode(empty_hash, false);

  EXPECT_EQ(hash_str,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

  const std::string_view nums_string = "1234567890";
  auto nums_span = std::span<const uint8_t>{
      reinterpret_cast<const uint8_t*>(nums_string.data()), nums_string.size()};
  hasher.update(nums_span);
  auto nums_hash = hasher.finish();
  hash_str = hex_encode(nums_hash, false);

  EXPECT_EQ(hash_str,
            "c775e7b757ede630cd0aa1113bd102661ab38829ca52a6422ab782862f268646");
}
}  // namespace HashBlazer::Test
