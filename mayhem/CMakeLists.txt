add_executable(fuzz_robots fuzz_parse.cpp)

target_compile_options(fuzz_robots PRIVATE -fsanitize=fuzzer,address,undefined)
target_link_options(fuzz_robots PRIVATE -fsanitize=fuzzer,address,undefined)

target_link_libraries(fuzz_robots robots)