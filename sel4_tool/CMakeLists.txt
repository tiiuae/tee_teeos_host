project (sel4-tool C CXX ASM)

add_library(${PROJECT_NAME}-lib STATIC
	sel4_tty_rpmsg.c
	sel4_tool_cmdline.c
	sel4_req.c
)

target_include_directories(${PROJECT_NAME}-lib
	INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable (${PROJECT_NAME}
	sel4_tool.c
)

target_link_libraries (${PROJECT_NAME}
	PRIVATE
		${PROJECT_NAME}-lib
)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
