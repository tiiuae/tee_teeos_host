# build an executable named system-services-example from system-services-example.c
# Cross compiler defined in soc_app.mk
# CC=$(CROSS_COMPILE)gcc
CFLAGS = -g -Werror -Wall # -Wpedantic ISO C forbids zero-size array 'keys' [-Werror=pedantic]

.PHONY: clean

all: sel4_tool.c
	$(CC) $(CFLAGS) -o sel4-tool sel4_tool.c sel4_tty_rpmsg.c sel4_tool_cmdline.c sel4_req.c

clean:
	$(RM) sel4-tool
