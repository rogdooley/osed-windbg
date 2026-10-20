cmake_minimum_required(VERSION 3.29)
project(rop_prove_target C)

if(NOT MSVC)
  message(FATAL_ERROR "rop_prove_target requires MSVC and WinDbg.")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(FATAL_ERROR "rop_prove_target must be configured with -A Win32 (PE32).")
endif()

add_executable(rop_prove_target rop_prove_target.c)
target_compile_definitions(rop_prove_target PRIVATE WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
target_compile_options(rop_prove_target PRIVATE /W4 /GS-)
target_link_options(rop_prove_target PRIVATE /DYNAMICBASE:NO /NXCOMPAT /INCREMENTAL:NO)
