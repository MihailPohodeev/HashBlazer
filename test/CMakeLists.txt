find_package(GTest REQUIRED)

function(add_new_test test_name)
    add_executable(${test_name}_test
        test_${test_name}.cxx
    )
    target_link_libraries(${test_name}_test PRIVATE
        hashblazer
        GTest::gtest
        GTest::gtest_main
    )
    add_test(NAME ${test_name} COMMAND ${test_name}_test)
endfunction()

add_new_test(base)
add_new_test(md5)
add_new_test(sha1)
add_new_test(sha224)
add_new_test(sha256)
add_new_test(sha384)
add_new_test(sha512)
