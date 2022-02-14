/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "sel4_tool_cmdline.h"

#include "sel4_req.h"
#include "sel4_circ.h"
#include "ree_tee_msg.h"
#include "sel4_tty_rpmsg.h"


#define DEVMEM_HANDLE           "/dev/mem"  /* For reading crashmem */
#define CRASHLOG_SIZE           0x2000      /* from devicetree */
#define CRASHLOG_PA             0xA2450000  /* from devicetree */

typedef int sync_spinlock_t; /* seL4 spinlock */

/* memory structure in the beginning of crashlog area */
struct crashlog_hdr {
    struct circ_buf_hdr circ_hdr;
    sync_spinlock_t writer_lock;
    sync_spinlock_t reader_lock;
};

int sel4_req_key_creation(uint32_t format, uint32_t nbits, uint32_t clientid,
                          const char *name, struct key_data_blob **output,
                          uint32_t *output_len)
{
    int ret = -1;

    struct ree_tee_key_resp_cmd *ret_cmd = NULL;

    struct ree_tee_key_req_cmd cmd = {
        .hdr.msg_type = REE_TEE_GEN_KEY_REQ,
        .hdr.length = sizeof(struct ree_tee_key_req_cmd),
        .key_req_info.format = format,
        .key_req_info.key_nbits = nbits,
        .key_req_info.client_id = clientid,
    };

    struct tty_msg tty = {
        .send_buf = (void *)&cmd,
        .send_len = cmd.hdr.length,
        .recv_buf = NULL,
        .recv_len = SKIP_LEN_CHECK,
        .recv_msg = REE_TEE_GEN_KEY_RESP,
        .status_check = VERIFY_TEE_OK,
    };

    if (!name || !output || !output_len) {
        printf("ERROR params: %s: %d\n", __FUNCTION__, __LINE__);
        ret = -EINVAL;
        goto out;
    }

    strcpy(cmd.key_req_info.name, name);

    ret = tty_req(&tty);
    if (ret < 0)
        goto out;

    if (ret < sizeof(struct ree_tee_key_resp_cmd)) {
        printf("Invalid msg size: %d\n", ret);
        ret = -EINVAL;
        goto out;
    }

    ret_cmd = (struct ree_tee_key_resp_cmd *)tty.recv_buf;

    printf("Pub Key length = %d, priv key length = %d\n",
           ret_cmd->key_blob.key_data_info.pubkey_length,
           ret_cmd->key_blob.key_data_info.privkey_length);

    size_t output_size = ret_cmd->key_blob.key_data_info.storage_size +
                         sizeof(struct ree_tee_key_info);

    printf("Storage blob size = %lu\n", output_size);

    *output = malloc(output_size);
    if (!*output) {
        printf("Out of memory: %s: %d\n", __FUNCTION__, __LINE__);
        ret = -ENOMEM;
        goto out;
    }

    memcpy(&(*output)->key_data_info, &ret_cmd->key_blob, output_size);

    *output_len = output_size;

    ret = 0;
out:

    free(tty.recv_buf);

    return ret;
}

int sel4_read_crashlog(const char *filename)
{
    ssize_t ret = -1;
    int fd = 0;
    int32_t read_len = 0;
    int dummy_lock = 0;

    char *crashlog_area = NULL;

    struct circ_ctx circ = { 0 };

    char *read_buf = malloc(CRASHLOG_SIZE);

    if (!read_buf) {
        printf("ERROR: out of memory: %s: %d\n", __FUNCTION__, __LINE__);
        ret = -ENOMEM;
        goto out;
    }

    if (!filename) {
        printf("ERROR params: %s: %d\n", __FUNCTION__, __LINE__);
        ret = -EINVAL;
        goto out;
    }

    fd = open(DEVMEM_HANDLE, O_RDWR);
    if (fd <= 0) {
        printf("failed to open %s: %d\n", DEVMEM_HANDLE, errno);
        ret = -EIO;
        goto out;
    }

    crashlog_area = mmap(NULL, CRASHLOG_SIZE, PROT_READ | PROT_WRITE,
                MAP_SHARED, fd, CRASHLOG_PA);

    if (crashlog_area == MAP_FAILED) {
        printf("ERROR: mmap: MAP_FAILED\n");
        ret = -EIO;
        goto out;
    }

    printf("crashlog_area: %p\n", crashlog_area);

    /* Setup ctrl struct for CIRC read */
    circ.hdr = (struct circ_buf_hdr *)crashlog_area;
    circ.buf = crashlog_area + sizeof(struct crashlog_hdr);

    ret = sel4_read_from_circ(&circ, CRASHLOG_SIZE, read_buf, &read_len,
                              &dummy_lock);
    if (ret) {
        printf("ERROR: sel4_read_from_circ: %ld\n", ret);
        goto out;
    }

    printf("crashlog size: %d\n", read_len);

    ret = sel4_tool_save_file(filename, (uint8_t *)read_buf, read_len);
    if (ret) {
        goto out;
    }

out:
    munmap(crashlog_area, CRASHLOG_SIZE);

    free(read_buf);

    return ret;
}

int sel4_req_key_import(struct key_data_blob *input_blob, uint32_t blob_size)
{
    ssize_t ret;

    struct tty_msg tty = {0};

    struct ree_tee_status_resp *ret_cmd = NULL;
    struct ree_tee_key_import_cmd *cmd = NULL;

    uint32_t cmd_len = sizeof(struct ree_tee_hdr) + blob_size;

    printf("cmd_len: %d\n", cmd_len);

    cmd = malloc(cmd_len);
    if (!cmd)
    {
        printf("ERROR: out of memory: %d\n", __LINE__);
        ret = -ENOMEM;
        goto out;
    }
    memset(cmd, 0x0, cmd_len);

    cmd->hdr.msg_type = REE_TEE_KEY_IMPORT_REQ;
    cmd->hdr.length = cmd_len;


    memcpy(&cmd->data_in, input_blob, blob_size);

    tty.send_buf = (void*)cmd;
    tty.send_len = cmd->hdr.length;
    tty.recv_buf = NULL;
    tty.recv_len = HDR_LEN;
    tty.recv_msg = REE_TEE_KEY_IMPORT_RESP;
    tty.status_check = VERIFY_TEE_OK;

    ret = tty_req(&tty);
    if (ret < 0)
        goto out;

    if (ret < sizeof(struct ree_tee_status_resp))
    {
        printf("Invalid msg size: %ld\n", ret);
        ret = -EINVAL;
        goto out;
    }

    ret_cmd = (struct ree_tee_status_resp*)tty.recv_buf;

    ret = ret_cmd->hdr.status;

out:
    if (cmd)
        free(cmd);

    return ret;
}