#ifndef UTILS_COMMON_HXX
#define UTILS_COMMON_HXX

#include <barrier>
#include <filesystem>
#include <fstream>
#include <ios>
#include <ranges>
#include <string_view>
#include <thread>
#include <vector>

#include "base.hxx"

namespace HashBlazer {

enum class HashingMode { BINARY, TEXT };

template <isHasher HasherType>
std::string calculateHashSumForFile(const std::filesystem::path& filepath,
                                    HashingMode mode = HashingMode::BINARY) {
  if (std::filesystem::is_directory(filepath))
    throw std::runtime_error{std::format("{}: {}: Is a directory",
                                         HASH_ALGO_NAME, filepath.string())};

  std::ifstream file{};
  [[likely]] if (mode == HashingMode::BINARY)
    file.open(filepath, std::ios::binary);
  else
    file.open(filepath);

  if (!file) throw std::runtime_error{"Can't open file!"};

  static constexpr size_t BUFFER_SIZE = 1'024 * 1'024;
  std::vector<uint8_t> buffer_1(BUFFER_SIZE, 0);
  std::vector<uint8_t> buffer_2(BUFFER_SIZE, 0);

  std::vector<uint8_t>* buf1 = &buffer_1;
  std::vector<uint8_t>* buf2 = &buffer_2;

  std::barrier sync_barrier(2, [&buf1, &buf2]() noexcept { std::swap(buf1, buf2); });

  auto read_func = [&sync_barrier, &file, &buf1, &buf2]() noexcept {
    bool is_last_block{false};
    while (true) {
      sync_barrier.arrive_and_wait();
      size_t bytes_read =
          file.read(reinterpret_cast<char*>(buf2->data() + sizeof(size_t) +
                                            sizeof(bool)),
                    static_cast<size_t>(buf2->size() - sizeof(size_t) -
                                        +sizeof(bool)))
              .gcount();
      [[unlikely]] if (is_last_block)
        break;
      is_last_block =
          (bytes_read < (buf2->size() - sizeof(size_t) - sizeof(bool)));
      std::memcpy(buf2->data(), &bytes_read, sizeof(size_t));
      std::memcpy(buf2->data() + sizeof(size_t), &is_last_block, sizeof(bool));
    }
  };

  auto func_hash_calc = [&sync_barrier, &file, &buf1, &buf2]() noexcept {
    HasherType hasher;
    while (true) {
      sync_barrier.arrive_and_wait();
      size_t bytes_read;
      std::memcpy(&bytes_read, buf1->data(), sizeof(size_t));
      bool is_last_block;
      std::memcpy(&is_last_block, buf1->data() + sizeof(size_t), sizeof(bool));
      hasher.update(std::span<uint8_t>(
          buf1->data() + sizeof(size_t) + sizeof(bool), bytes_read));
      [[unlikely]] if (is_last_block)
        return hex_encode(hasher.finish(), false);
    }
  };

  [[maybe_unused]] std::jthread hash_calc_thread{read_func};
  std::string hash_str = func_hash_calc();

  return hash_str;
}

inline bool is_flag(std::string_view arg) {
  return !arg.empty() && arg[0] == '-';
}

template <isHasher HasherType, std::ranges::input_range Range>
  requires std::same_as<std::ranges::range_value_t<Range>,
                        std::filesystem::path>
void calculateAndPrintHashSumForFiles(Range&& filepaths,
                                      HashingMode mode = HashingMode::BINARY,
                                      bool is_tag_output = false) {
  for (const auto& filepath : filepaths) {
    try {
      std::string hash_str =
          HashBlazer::calculateHashSumForFile<HasherType>(filepath);

      [[unlikely]] if (is_tag_output)
        std::cout << std::format("{} ({}) = {}", HASH_ALGO_NAME,
                                 filepath.string(), hash_str)
                  << std::endl;
      else
        std::cout << std::format(
                         "{}{}{}", hash_str,
                         (mode == HashBlazer::HashingMode::BINARY ? " *"
                                                                  : "  "),
                         filepath.string())
                  << std::endl;
    } catch (const std::exception& error) {
      std::cerr << error.what() << std::endl;
    }
  }
}

template <isHasher HasherType, std::ranges::input_range Range>
  requires std::same_as<std::ranges::range_value_t<Range>,
                        std::filesystem::path>
void checkFileFromFile(Range&& files, HashingMode mode = HashingMode::BINARY) {
  // TODO...
}

}  // namespace HashBlazer

#endif  // UTILS_COMMON_HXX
