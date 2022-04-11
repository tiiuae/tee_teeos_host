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

add_compile_definitions(
	DEBUGLEVEL_true 		# teec_trace: enable dump_buffer function
	DEBUGLEVEL=TRACE_ERROR	# teec_trace: TRACE_ERROR, TRACE_INFO, TRACE_DEBUG, TRACE_FLOW
#	SEL4_PRINT_PARAM_MEMREF # sel4_serializer: print serialized memref contents
	SEL4LOG_ERROR			# sel4_log
#	SEL4LOG_INFO			# sel4_log
#	TRACE_PKCS11_API_CALLS 	# pkcs11_api.c
	_GNU_SOURCE				# F_OFD_SETLK
)

add_subdirectory(sel4_tool)

add_subdirectory(optee_client)
