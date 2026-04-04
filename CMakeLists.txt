cmake_minimum_required(VERSION 3.25)
list(APPEND CMAKE_MESSAGE_CONTEXT HashBlazer)
project(HashBlazer VERSION 0.0.1)

include(CTest)

set( CMAKE_CXX_STANDARD           20  )
set( CMAKE_CXX_STANDARD_REQUIRED  ON  )
set( CMAKE_CXX_EXTENSIONS         OFF )
set( CMAKE_LINK_LIBRARIES_ONLY_TARGETS ON )

option(BUILD_HASHSUM_UTILS "Build hashsum utils." ON)

set(HASH_BLAZER_LIBRARY_SOURCE_FILES
  include/base.hxx
  include/md5.hxx
  include/sha1.hxx
  include/sha224.hxx
  include/sha256.hxx
  include/sha384.hxx
  include/sha512.hxx

  src/base.cxx
  src/md5.cxx
  src/sha1.cxx
  src/sha224.cxx
  src/sha256.cxx
  src/sha384.cxx
  src/sha512.cxx
)
add_library(hashblazer ${HASH_BLAZER_LIBRARY_SOURCE_FILES})
target_include_directories(hashblazer PUBLIC include)

if (BUILD_HASHSUM_UTILS)
  list(APPEND CMAKE_MESSAGE_CONTEXT HashSum_Utils)

  find_package(cxxopts REQUIRED)

  function(add_hashsum_utility utility_name)
    string(TOLOWER ${utility_name} lower_name)
    string(TOUPPER ${utility_name} upper_name)

    message(STATUS ${lower_name}sum)

    set(target_name ${lower_name}sum)
    set(compile_definition BUILD_${upper_name}SUM_APP)

    add_executable(${target_name}
      src/utils_common.hxx
      src/main.cxx
    )
    target_link_libraries(${target_name}
      PRIVATE
        hashblazer
        cxxopts::cxxopts
    )
    target_compile_definitions(${target_name}
      PRIVATE
        ${compile_definition}
        HASH_BLAZER_VERSION="${PROJECT_VERSION}"
    )
  endfunction()

  add_hashsum_utility(md5)
  add_hashsum_utility(sha1)
  add_hashsum_utility(sha224)
  add_hashsum_utility(sha256)
  add_hashsum_utility(sha384)
  add_hashsum_utility(sha512)

endif()

if (BUILD_TESTING)
  enable_testing()
  add_subdirectory(test)
endif()
