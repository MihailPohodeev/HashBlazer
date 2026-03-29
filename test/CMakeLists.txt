find_package(GTest REQUIRED)

add_executable(md5_test
    test_md5.cxx
)
target_link_libraries(md5_test PRIVATE
    hashblazer
    GTest::gtest
    GTest::gtest_main
)
add_test(NAME md5 COMMAND md5_test)

add_executable(base_test
    test_base.cxx
)
target_link_libraries(base_test PRIVATE
    hashblazer
    GTest::gtest
    GTest::gtest_main
)
add_test(NAME base COMMAND base_test)
