#include <cstdio>
#include <cxxopts.hpp>
#include <format>
#include <fstream>
#include <iostream>
#include <vector>

#include "base.hxx"
#if defined(BUILD_MD5SUM_APP)

#include "md5.hxx"
using HasherType = HashBlazer::MD5_Hasher;
#define HASH_ALGO_NAME "MD5"
#define HASH_ALGO_SIZE "(128-bit)"

#elif defined(BUILD_SHA1SUM_APP)

#include "sha1.hxx"
using HasherType = HashBlazer::SHA1_Hasher;
#define HASH_ALGO_NAME "SHA1"
#define HASH_ALGO_SIZE "(160-bit)"

#elif defined(BUILD_SHA224SUM_APP)

#include "sha224.hxx"
using HasherType = HashBlazer::SHA224_Hasher;
#define HASH_ALGO_NAME "SHA224"
#define HASH_ALGO_SIZE "(224-bit)"

#elif defined(BUILD_SHA256SUM_APP)

#include "sha256.hxx"
using HasherType = HashBlazer::SHA256_Hasher;
#define HASH_ALGO_NAME "SHA256"
#define HASH_ALGO_SIZE "(256-bit)"

#elif defined(BUILD_SHA384SUM_APP)

#include "sha384.hxx"
using HasherType = HashBlazer::SHA384_Hasher;
#define HASH_ALGO_NAME "SHA384"
#define HASH_ALGO_SIZE "(384-bit)"

#elif defined(BUILD_SHA512SUM_APP)

#include "sha512.hxx"
using HasherType = HashBlazer::SHA512_Hasher;
#define HASH_ALGO_NAME "SHA512"
#define HASH_ALGO_SIZE "(512-bit)"

#else
#error "Specify hasher type."
#endif

#ifndef HASH_BLAZER_VERSION
#error "HASH_BLAZER_VERSION marco shoud be specified."
#endif

#include "utils_common.hxx"

namespace fs = std::filesystem;

int main_impl(int argc, char** argv) {
  //===========================================================================================
  //                                    HANDLE ARGUMENTS
  //===========================================================================================

  // clang-format off
  cxxopts::Options options{argv[0],
                           "Print or check " HASH_ALGO_NAME " " HASH_ALGO_SIZE " checksums."};
  options.add_options()
    ("b,binary", "read in binary mode")
    ("t,text", "read in text mode (default)")
    ("c,check", "read checksums from the FILEs and check them")
    ("z,zero","end each output line with NUL, not newline, and disable file name escaping")
    ("tag", "create a BSD-style checksum")
    ("h,help", "display this help and exit")
    ("v,version", "output version information and exit")
    ("w,warn", "warn about improperly formatted checksum lines")
    ("s,status", "don't output anything, status code shows success")
    ("strict", "exit non-zero for improperly formatted checksum lines")
    ("q,quiet", "don't print OK for each successfully verified file")
    ("i,ignore-missing", "don't fail or report status for missing files")
    ;
  // clang-format on
  options.allow_unrecognised_options();

  auto cmd_args_parsing_result = options.parse(argc, argv);

  // all unmatched files is filepaths.
  auto&& unmatched = cmd_args_parsing_result.unmatched();
  std::vector<fs::path> files;
  for (const auto& elem : unmatched) {
    if (HashBlazer::is_flag(elem))
      throw std::runtime_error{"unrecognized option '" + elem + "'"};
    files.push_back(elem);
  }

  if (cmd_args_parsing_result.count("help")) {
    std::cout << options.help() << std::endl;
    return 0;
  }

  if (cmd_args_parsing_result.count("version")) {
    constexpr std::string_view version_str =
        "(HashBlazer) " HASH_BLAZER_VERSION;
    std::cout << argv[0] << " " << version_str << std::endl;
    return 0;
  }

  auto mode = HashBlazer::HashingMode::TEXT;
  if (cmd_args_parsing_result.count("binary"))
    mode = HashBlazer::HashingMode::BINARY;

  bool is_tag_output = cmd_args_parsing_result.count("tag");
  if (is_tag_output) {
    if (cmd_args_parsing_result.count("text")) {
      return -1;
    }
    mode = HashBlazer::HashingMode::BINARY;
  }

  //===========================================================================================
  //                                    PROCESS DATA
  //===========================================================================================

  if (cmd_args_parsing_result.count("check"))
    std::ignore;
  else
    HashBlazer::calculateAndPrintHashSumForFiles<HasherType>(files, mode,
                                                             is_tag_output);

#if 0
  for (size_t i = 0; i < hash_futures_with_result.size(); ++i) {
    std::string result_hash;

    try {
      result_hash = hash_futures_with_result[i].get();
    } catch (const std::exception& error) {
      std::cerr << argv[0] << ": " << error.what() << std::endl;
      continue;
    }

    std::string result_string;
    if (is_tag_output)
      result_string = std::format("{} ({}) = {}", HASH_ALGO_NAME,
                                  files[i].string(), result_hash);
    else
      result_string =
          std::format("{}{}{}", result_hash,
                      (mode == HashBlazer::HashingMode::BINARY ? " *" : "  "),
                      files[i].string());

    std::cout << result_string << std::endl;
  }
#endif
  return 0;
}

int main(int argc, char** argv) {
  try {
    return main_impl(argc, argv);
  } catch (std::exception& error) {
    std::cerr << argv[0] << ": " << error.what() << std::endl
              << "Try '" << argv[0] << " --help' for more information."
              << std::endl;
  }
  return -1;
}
