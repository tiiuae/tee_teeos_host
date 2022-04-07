/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SEL4_TOOL_CMDLINE_H_
#define _SEL4_TOOL_CMDLINE_H_

#include <stdint.h>

enum tool_cmd {
    TOOL_CMD_INVALID = 0,
    TOOL_CMD_READ_CRASHLOG,
    TOOL_CMD_DEBUG_FLAGS,
    TOOL_CMD_OPTEE_INIT,
    TOOL_CMD_OPTEE_EXPORT_STORAGE,

    /* For testing/debug purposes */
    TOOL_CMD_TEST_STATUS,
    TOOL_CMD_TEST_UNKNOWN_CMD,
    TOOL_CMD_TEST_INV_SEND_LEN,
    TOOL_CMD_TEST_INV_RECV_LEN,
};

int sel4_tool_load_file(const char *storage_path, uint8_t **storage, uint32_t *storage_len);
int sel4_tool_save_file(const char *storage_path, uint8_t *storage, uint32_t storage_len);
int sel4_tool_parse_opts(int argc, char* argv[], char **infile, char **outfile, uint32_t *cmd, uint64_t *flags);

#endif /* _SEL4_TOOL_CMDLINE_H_ */