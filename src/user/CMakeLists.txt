set(USER_SOURCES
    main.cpp
    logger.cpp
    bpf_loader.cpp
    skeleton_wrapper.cpp
)

add_executable(file_monitor ${USER_SOURCES})

target_link_libraries(file_monitor
    PRIVATE
        libbpf_static
        elf
        z
        Threads::Threads
)

target_include_directories(file_monitor
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/external/libbpf/include
        ${CMAKE_BINARY_DIR}/external/libbpf
        ${CMAKE_BINARY_DIR}/src/ebpf
)

install(TARGETS file_monitor DESTINATION bin)