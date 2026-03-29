#include "base.hxx"

#include <string_view>

namespace HashBlazer {
std::string hex_encode(std::span<const uint8_t> data, bool uppercase) {
  constexpr static std::string_view hex_lower_chars = "0123456789abcdef";
  constexpr static std::string_view hex_upper_chars = "0123456789ABCDEF";
  std::string result{};
  result.reserve(data.size() * 2);

  const std::string_view &target_charset =
      (uppercase ? hex_upper_chars : hex_lower_chars);
  for (uint8_t byte : data) {
    result.push_back(target_charset[byte >> 4]);
    result.push_back(target_charset[byte & 0x0F]);
  }
  return result;
}
}  // namespace HashBlazer
