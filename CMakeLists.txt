cmake_minimum_required (VERSION 3.4)

project (teeos_host C CXX ASM)


################################################################################
# Compiler flags from optee build
#
# removed: -Wcast-align
################################################################################
add_compile_options (
	-Wall -Wbad-function-cast
	-Werror-implicit-function-declaration -Wextra
	-Wfloat-equal -Wformat-nonliteral -Wformat-security
	-Wformat=2 -Winit-self -Wmissing-declarations
	-Wmissing-format-attribute -Wmissing-include-dirs
	-Wmissing-noreturn -Wmissing-prototypes -Wnested-externs
	-Wpointer-arith -Wshadow -Wstrict-prototypes
	-Wswitch-default -Wunsafe-loop-optimizations
	-Wwrite-strings -fPIC
	-Werror
)

add_subdirectory(sel4_tool)

add_subdirectory(optee_client)
