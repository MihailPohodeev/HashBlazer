#ifndef UTILS_COMMON_HXX
#define UTILS_COMMON_HXX

#include <filesystem>
#include <fstream>
#include <ios>
#include <string_view>

#include "base.hxx"

namespace HashBlazer {

enum class HashingMode { BINARY, TEXT };

template <isHasher HasherType>
std::string calculateHashSumForFile(const std::filesystem::path& filepath,
                                    HashingMode mode = HashingMode::BINARY) {
  static constexpr size_t BUFFER_SIZE = 1'024 * 1'024 * 2;

  HasherType hasher;

  std::ifstream file;
  if (mode == HashingMode::BINARY)
    file.open(filepath, std::ios::binary);
  else if (mode == HashingMode::TEXT)
    file.open(filepath);

  if (!file) throw std::runtime_error{"Can't open file : " + filepath.string()};

  std::vector<char> buffer(BUFFER_SIZE);
  while (file.read(buffer.data(), buffer.size()).gcount() > 0) {
    hasher.update(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(buffer.data()), file.gcount()));
  }
  auto result_vector = hasher.finish();

  auto result = hex_encode(result_vector, false);
  return result;
}

bool is_flag(std::string_view arg) { return !arg.empty() && arg[0] == '-'; }

}  // namespace HashBlazer

#endif  // UTILS_COMMON_HXX
