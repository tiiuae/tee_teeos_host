/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "sel4_tool_cmdline.h"

int sel4_tool_load_file(const char *storage_path, uint8_t **storage, uint32_t *storage_len)
{
    int fd = 0;
    int err = -1;
    struct stat file_stat = {0};
    uint8_t *bin = NULL;
    ssize_t read_bytes = 0;

    fd = open(storage_path, O_RDONLY);
    if(fd <= 0)
    {
        printf("failed to open %s: %d\n", storage_path, errno);
        err = -EIO;
        goto out;
    }

    err = fstat(fd, &file_stat);
    if (err)
    {
        printf("failed to stat %s: %d\n", storage_path, errno);
        err = -EIO;
        goto out;
    }

    printf("file size: %ld\n", file_stat.st_size);;

    bin = malloc(file_stat.st_size);
    if (!bin)
    {
         printf("Out of memory: %s: %d\n", __FUNCTION__, __LINE__);
         err = -ENOMEM;
         goto out;
    }

    read_bytes = read(fd, bin, file_stat.st_size);
    if (read_bytes != file_stat.st_size)
    {
        printf("ERROR: read len: %ld (%ld)\n", read_bytes, file_stat.st_size);
        err = -EIO;
        goto out;
    }

    *storage_len = read_bytes;
    *storage = bin;

out:
    /* on failure free allocated buffer*/
    if (err && bin)
        free(bin);

    if (fd > 0)
        close(fd);

    return err;
}

int sel4_tool_save_file(const char *storage_path, uint8_t *storage, uint32_t storage_len)
{
    int fd = 0;
    int err = -1;
    ssize_t written = 0;

    fd = open(storage_path, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
    if(fd <= 0)
    {
        printf("failed to open %s: %d\n", storage_path, errno);
        err = -EIO;
        goto out;
    }

    written = write(fd, storage, storage_len);
    if (written < 0)
    {
        printf("ERROR write: %d\n", errno);
        err = -EIO;
        goto out;
    }

    if (written != storage_len)
    {
        printf("ERROR write len: %ld (%d)\n", written, storage_len);
        err = -EIO;
        goto out;
    }

    err = 0;
out:
    if (fd > 0)
        close(fd);

    return err;
}

static void print_usage(const char *prog_name)
{
    printf("Usage:\n");
    printf("    -i storage_path        Path to load storage blob\n");
    printf("    -o storage_path        Path to store storage blob\n");
    printf("    -c tool_cmd            Run sel4-tool cmd\n");

    printf("\nTOOL_CMD_READ_CRASHLOG:\n");
    printf("    %s -o crashlog_file -c %d\n", prog_name, TOOL_CMD_READ_CRASHLOG);
    printf("\nTOOL_CMD_OPTEE_INIT:\n");
    printf("    %s [ -i optee_storage ] -c %d\n", prog_name, TOOL_CMD_OPTEE_INIT);
    printf("\nTOOL_CMD_OPTEE_EXPORT_STORAGE:\n");
    printf("    %s -o optee_storage -c %d\n", prog_name, TOOL_CMD_OPTEE_EXPORT_STORAGE);
    printf("\nTesting / Debug commands:\n");
    printf("TOOL_CMD_TEST_STATUS:        ");
    printf("%s -c %d\n", prog_name, TOOL_CMD_TEST_STATUS);
    printf("TOOL_CMD_TEST_UNKNOWN_CMD:   ");
    printf("%s -c %d\n", prog_name, TOOL_CMD_TEST_UNKNOWN_CMD);
    printf("TOOL_CMD_TEST_INV_SEND_LEN:  ");
    printf("%s -c %d\n", prog_name, TOOL_CMD_TEST_INV_SEND_LEN);
    printf("TOOL_CMD_TEST_INV_RECV_LEN:  ");
    printf("%s -c %d\n", prog_name, TOOL_CMD_TEST_INV_RECV_LEN);
    printf("Set SEL4 debug flags:        ");
    printf("%s -d <debug mask as a decimal number> \n", prog_name);

    printf("\n");
}

int sel4_tool_parse_opts(int argc, char* argv[], char **infile, char **outfile, uint32_t *cmd, uint64_t *debug_flags)
{
    int opt = 0;

    char *str_opt = NULL;

    while ((opt = getopt(argc, argv, "i:o:c:f:")) != -1)
    {
        switch (opt) {
        case 'i':
            str_opt = malloc(strlen(optarg) + 1);
            if (!str_opt)
            {
                printf("ERROR out of memory: %s: %d\n", __FUNCTION__, __LINE__);
                return -ENOMEM;
            }
            strncpy(str_opt, optarg, strlen(optarg) + 1);
            *infile = str_opt;
            break;

        case 'o':
            str_opt = malloc(strlen(optarg) + 1);
            if (!str_opt)
            {
                printf("ERROR out of memory: %s: %d\n", __FUNCTION__, __LINE__);
                return -ENOMEM;
            }
            strncpy(str_opt, optarg, strlen(optarg) + 1);
            *outfile = str_opt;
            break;

        case 'c':
            *cmd = atoi(optarg);
            break;
        case 'f':
            *cmd = TOOL_CMD_DEBUG_FLAGS;
            *debug_flags = atoll(optarg);
            break;
        default:
            print_usage(argv[0]);
            return -EPERM;
        }
    }

    return 0;
}