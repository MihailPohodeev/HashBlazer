cmake_minimum_required(VERSION 3.25)
project(HashBlazer VERSION 0.0.1)

include(CTest)

set( CMAKE_CXX_STANDARD           20  )
set( CMAKE_CXX_STANDARD_REQUIRED  ON  )
set( CMAKE_CXX_EXTENSIONS         OFF )

option(BUILD_HASHSUM_UTILS "Build hashsum utils." ON)

set(HASH_BLAZER_LIBRARY_SOURCE_FILES
  include/md5.hxx
  include/base.hxx
  src/md5.cxx
  src/base.cxx
)
add_library(hashblazer ${HASH_BLAZER_LIBRARY_SOURCE_FILES})
target_include_directories(hashblazer PUBLIC include)

if (BUILD_HASHSUM_UTILS)
  find_package(cxxopts REQUIRED)

  set(HASH_BLAZER_UTILS_SOURCE_FILES
    src/utils_common.hxx
    src/main.cxx
  )

  add_executable(md5sum ${HASH_BLAZER_UTILS_SOURCE_FILES})
  target_link_libraries(md5sum PRIVATE hashblazer cxxopts::cxxopts)
  target_compile_definitions(md5sum
    PRIVATE
      BUILD_MD5SUM_APP
      HASH_BLAZER_VERSION="${PROJECT_VERSION}"
  )
endif()

if (BUILD_TESTING)
  enable_testing()
  add_subdirectory(test)
endif()
