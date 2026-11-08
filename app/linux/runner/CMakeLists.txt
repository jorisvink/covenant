cmake_minimum_required(VERSION 3.13)
project(runner LANGUAGES C CXX)

set(COVENANT_ROOT "${CMAKE_SOURCE_DIR}/../..")
set(COVENANT_DEPS "${COVENANT_ROOT}/build/host")

configure_file("${FLUTTER_MANAGED_DIR}/generated_plugin_registrant.cc"
  "${CMAKE_CURRENT_BINARY_DIR}/generated_plugin_registrant.c" COPYONLY)

add_executable(${BINARY_NAME}
  "main.c"
  "covenant.c"
  "dialog.c"
  "${CMAKE_CURRENT_BINARY_DIR}/generated_plugin_registrant.c"
)

target_compile_options(${BINARY_NAME} PRIVATE
  "$<$<COMPILE_LANGUAGE:C>:-std=c99;-D_DEFAULT_SOURCE;-Wall;-Werror>"
  "$<$<COMPILE_LANGUAGE:C>:-Wmissing-prototypes;-Wmissing-declarations>"
  "$<$<COMPILE_LANGUAGE:C>:-Wshadow;-Wpointer-arith;-Wsign-compare>"
  "$<$<COMPILE_LANGUAGE:C>:-fstack-protector-all>")
target_compile_options(${BINARY_NAME} PRIVATE
  "$<$<NOT:$<CONFIG:Debug>>:-O2>")
target_compile_definitions(${BINARY_NAME} PRIVATE
  "$<$<NOT:$<CONFIG:Debug>>:NDEBUG>")

target_include_directories(${BINARY_NAME} PRIVATE
  "${CMAKE_SOURCE_DIR}" "${FLUTTER_MANAGED_DIR}" "${COVENANT_ROOT}/include"
  "${COVENANT_ROOT}/nyfe/include" "${COVENANT_DEPS}/include")

target_link_libraries(${BINARY_NAME} PRIVATE flutter PkgConfig::GTK
  -Wl,--start-group
  "${COVENANT_ROOT}/libcovenant.a"
  "${COVENANT_DEPS}/lib/libkyrka.a"
  "${COVENANT_DEPS}/mbedtls/lib/libmbedcrypto.a"
  "${COVENANT_DEPS}/libsodium/lib/libsodium.a"
  -Wl,--end-group
  pthread)
