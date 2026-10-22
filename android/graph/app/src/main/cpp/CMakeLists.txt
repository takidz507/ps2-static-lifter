cmake_minimum_required(VERSION 3.22.1)
project("ps2_lifted_graph" C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Zero emulator / interpreter components — pure AOT lifted R5900 C code + runtime + GS boundary model
add_library(
    ps2_lifted_graph
    SHARED
    native_graph_jni.c
    ps2_runtime.c
    lifted_graph.c
)

find_library(log-lib log)

target_link_libraries(
    ps2_lifted_graph
    ${log-lib}
    m
)
