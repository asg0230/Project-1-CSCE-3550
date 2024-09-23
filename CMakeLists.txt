cmake_minimum_required(VERSION 3.10) 


project(Project1)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Adding executable targets
add_executable(main_app src/main.cpp)  # Assumes your main code is in src/main.cpp

# Google Test
enable_testing()
add_subdirectory(googletest)  # Path to the Google Test source
include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})


add_executable(unit_tests tests/unit_tests.cpp)  

target_link_libraries(unit_tests gtest gtest_main)

# Adding a test to CMake
add_test(NAME unit_test COMMAND unit_tests)
