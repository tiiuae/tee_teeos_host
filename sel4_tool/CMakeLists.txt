project (sel4-tool C CXX ASM)

add_executable (${PROJECT_NAME}
	sel4_tool.c
	sel4_tty_rpmsg.c
	sel4_tool_cmdline.c
	sel4_req.c
)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
