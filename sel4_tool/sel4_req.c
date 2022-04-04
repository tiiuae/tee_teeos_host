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

#include "sel4_req.h"
#include "sel4_circ.h"
#include "ree_tee_msg.h"
#include "sel4_tty_rpmsg.h"

#include "sel4_log.h"

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
        .send = {{
            .buf = (void*)&cmd,
            .buf_len = cmd.hdr.length
        },},
        .recv_buf = NULL,
        .recv_len = SKIP_LEN_CHECK,
        .recv_msg = REE_TEE_GEN_KEY_RESP,
        .status_check = VERIFY_TEE_OK,
    };

    if (!name || !output || !output_len) {
        SEL4LOGE("ERROR params: %s: %d\n", __FUNCTION__, __LINE__);
        ret = -EINVAL;
        goto out;
    }

    strcpy(cmd.key_req_info.name, name);

    ret = tty_req(&tty);
    if (ret < 0)
        goto out;

    if (ret < (ssize_t)sizeof(struct ree_tee_key_resp_cmd)) {
        SEL4LOGE("Invalid msg size: %d\n", ret);
        ret = -EINVAL;
        goto out;
    }

    ret_cmd = (struct ree_tee_key_resp_cmd *)tty.recv_buf;

    SEL4LOGI("Pub Key length = %d, priv key length = %d\n",
           ret_cmd->key_blob.key_data_info.pubkey_length,
           ret_cmd->key_blob.key_data_info.privkey_length);

    size_t output_size = ret_cmd->key_blob.key_data_info.storage_size +
                         sizeof(struct ree_tee_key_info);

    SEL4LOGI("Storage blob size = %lu\n", output_size);

    *output = malloc(output_size);
    if (!*output) {
        SEL4LOGE("Out of memory: %s: %d\n", __FUNCTION__, __LINE__);
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

int sel4_read_crashlog(char **crashlog, uint32_t *crashlog_len)
{
    ssize_t ret = -1;
    int fd = 0;
    int32_t read_len = 0;
    int dummy_lock = 0;

    char *crashlog_area = NULL;

    struct circ_ctx circ = { 0 };

    char *read_buf = malloc(CRASHLOG_SIZE);

    if (!read_buf) {
        SEL4LOGE("ERROR: out of memory: %s: %d\n", __FUNCTION__, __LINE__);
        ret = -ENOMEM;
        goto err_out;
    }

    if (!crashlog) {
        SEL4LOGE("ERROR params: %s: %d\n", __FUNCTION__, __LINE__);
        ret = -EINVAL;
        goto err_out;
    }

    fd = open(DEVMEM_HANDLE, O_RDWR);
    if (fd <= 0) {
        SEL4LOGE("failed to open %s: %d\n", DEVMEM_HANDLE, errno);
        ret = -EIO;
        goto err_out;
    }

    crashlog_area = mmap(NULL, CRASHLOG_SIZE, PROT_READ | PROT_WRITE,
                MAP_SHARED, fd, CRASHLOG_PA);

    if (crashlog_area == MAP_FAILED) {
        SEL4LOGE("ERROR: mmap: MAP_FAILED\n");
        ret = -EIO;
        goto err_out;
    }

    SEL4LOGI("crashlog_area: %p\n", crashlog_area);

    /* Setup ctrl struct for CIRC read */
    circ.hdr = (struct circ_buf_hdr *)crashlog_area;
    circ.buf = crashlog_area + sizeof(struct crashlog_hdr);

    ret = sel4_read_from_circ(&circ, CRASHLOG_SIZE, read_buf, &read_len,
                              &dummy_lock);
    if (ret) {
        SEL4LOGE("ERROR: sel4_read_from_circ: %ld\n", ret);
        goto err_out;
    }

    SEL4LOGI("crashlog size: %d\n", read_len);


    *crashlog = read_buf;
    *crashlog_len = read_len;

    munmap(crashlog_area, CRASHLOG_SIZE);

    return ret;

err_out:
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

    SEL4LOGI("cmd_len: %d\n", cmd_len);

    cmd = malloc(cmd_len);
    if (!cmd)
    {
        SEL4LOGE("ERROR: out of memory: %d\n", __LINE__);
        ret = -ENOMEM;
        goto out;
    }
    memset(cmd, 0x0, cmd_len);

    cmd->hdr.msg_type = REE_TEE_KEY_IMPORT_REQ;
    cmd->hdr.length = cmd_len;


    memcpy(&cmd->data_in, input_blob, blob_size);

    tty.send[0].buf = (void*)&cmd,
    tty.send[0].buf_len = cmd->hdr.length,
    tty.recv_buf = NULL;
    tty.recv_len = HDR_LEN;
    tty.recv_msg = REE_TEE_KEY_IMPORT_RESP;
    tty.status_check = VERIFY_TEE_OK;

    ret = tty_req(&tty);
    if (ret < 0)
        goto out;

    if (ret < (ssize_t)sizeof(struct ree_tee_status_resp))
    {
        SEL4LOGE("Invalid msg size: %ld\n", ret);
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

int sel4_req_debug_config(uint64_t *debug_flags)
{
    ssize_t ret;

    struct tty_msg tty = {0};

    struct ree_tee_config_cmd *ret_cmd = NULL;
    struct ree_tee_config_cmd cmd = {0};

    uint32_t cmd_len = sizeof(struct ree_tee_config_cmd);

    SEL4LOGI("cmd_len: %d\n", cmd_len);


    cmd.hdr.msg_type = REE_TEE_CONFIG_REQ;
    cmd.hdr.length = cmd_len;
    cmd.debug_config = *debug_flags;



    tty.send[0].buf = (void*)&cmd,
    tty.send[0].buf_len = cmd.hdr.length,
    tty.recv_buf = NULL;
    tty.recv_len = cmd_len;
    tty.recv_msg = REE_TEE_CONFIG_RESP;
    tty.status_check = VERIFY_TEE_OK;

    ret = tty_req(&tty);
    if (ret < 0)
        goto out;

    if (ret < (ssize_t)sizeof(struct ree_tee_config_cmd))
    {
        SEL4LOGE("Invalid msg size: %ld\n", ret);
        ret = -EINVAL;
        goto out;
    }

    ret_cmd = (struct ree_tee_config_cmd*)tty.recv_buf;

    ret = ret_cmd->hdr.status;
    *debug_flags = ret_cmd->debug_config;
    SEL4LOGI("Debug flag was %lu \n", *debug_flags);

out:
    return ret;
}

static int sel4_optee_invoke_ta(uint32_t optee_cmd,
                                uint32_t ta_cmd,
                                char **params_in_out,
                                uint32_t *in_out_len,
                                int32_t *tee_err,
                                uint32_t *ta_err)
{
    int ret = -1;

    char *params_in = *params_in_out;
    uint32_t in_len = *in_out_len;
    char *params_out = NULL;
    uint32_t out_len = 0;

    struct ree_tee_optee_cmd *resp = NULL;

    struct ree_tee_optee_cmd req = {
        .hdr.msg_type = REE_TEE_OPTEE_CMD_REQ,
        .hdr.length = sizeof(struct ree_tee_optee_cmd) + in_len,
        .cmd.optee_cmd = optee_cmd,
        .cmd.ta_cmd = ta_cmd,
    };

    struct tty_msg tty = {
        .send = {
            {
                .buf = (void*)&req,
                .buf_len = sizeof(struct ree_tee_optee_cmd)
            },
            {
                .buf = params_in,
                .buf_len = in_len
            },
        },
        .recv_buf = NULL,
        .recv_len = SKIP_LEN_CHECK,
        .recv_msg = REE_TEE_OPTEE_CMD_RESP,
        .status_check = SKIP_TEE_OK_CHECK,
    };

    SEL4LOGI("%s: optee_cmd: %d, ta_cmd: %d\n", __FUNCTION__, optee_cmd, ta_cmd);

    ret = tty_req(&tty);
    if (ret < 0)
        goto out;

    if (ret < (ssize_t)(sizeof(struct ree_tee_optee_cmd))) {
        SEL4LOGE("Invalid msg size: %d\n", ret);
        ret = -EINVAL;
        goto out;
    }

    resp = (struct ree_tee_optee_cmd *)tty.recv_buf;

    *tee_err = resp->hdr.status;
    *ta_err = resp->cmd.ta_result;

    SEL4LOGI("%s: recv: tee_err: %d, ta_err: 0x%x\n", __FUNCTION__, *tee_err, *ta_err);

    /* TEE error, no need to process TA params */
    if (*tee_err != TEE_OK) {
        ret = 0;
        goto out;
    }

    out_len = ret - (ssize_t)(sizeof(struct ree_tee_optee_cmd));

    SEL4LOGI("%s: recv: %d, param len: %d\n", __FUNCTION__, ret, out_len);

    params_out = malloc(out_len);
    if (!params_out) {
        SEL4LOGE("out of memory\n");
        ret = -ENOMEM;
        goto out;
    }

    memcpy(params_out, resp->cmd.params, out_len);

    /* return out buffer */
    free(*params_in_out);

    *params_in_out = params_out;
    *in_out_len = out_len;

    ret = 0;
out:
    free(tty.recv_buf);

    return ret;
}

int sel4_optee_init()
{
    ssize_t ret = -1;

    struct ree_tee_status_req cmd = {
        .hdr.msg_type = REE_TEE_OPTEE_INIT_REQ,
        .hdr.length = HDR_LEN,
    };

    struct tty_msg tty = {
        .send = {{
            .buf = (void*)&cmd,
            .buf_len = cmd.hdr.length
        },},
        .recv_buf = NULL,
        .recv_len = HDR_LEN,
        .recv_msg = REE_TEE_OPTEE_INIT_RESP,
        .status_check = VERIFY_TEE_OK,
    };

    ret = tty_req(&tty);
    if (ret < 0)
    {
        SEL4LOGE("Status message failed: %ld \n", ret);
        goto out;
    }

    ret = 0;

out:
    free(tty.recv_buf);

    return ret;
}

int sel4_optee_open_session(char **params_in_out,uint32_t *in_out_len,
                            int32_t *tee_err, uint32_t *ta_err)
{
    if (!params_in_out ||
        !*params_in_out ||
        !in_out_len ||
        !tee_err ||
        !ta_err) {
        return -EINVAL;
    }

    return sel4_optee_invoke_ta(OPTEE_OPEN_SESSION,
                                TA_CMD_NA,
                                params_in_out,
                                in_out_len,
                                tee_err,
                                ta_err);
}

int sel4_optee_close_session(char **params_in_out,uint32_t *in_out_len,
                            int32_t *tee_err, uint32_t *ta_err)
{
    if (!params_in_out ||
        !*params_in_out ||
        !in_out_len ||
        !tee_err ||
        !ta_err) {
        return -EINVAL;
    }

    return sel4_optee_invoke_ta(OPTEE_CLOSE_SESSION,
                                TA_CMD_NA,
                                params_in_out,
                                in_out_len,
                                tee_err,
                                ta_err);
}

int sel4_optee_invoke_cmd(uint32_t ta_cmd, char **params_in_out, uint32_t *in_out_len, int32_t *tee_err, uint32_t *ta_err)
{
    if (!params_in_out ||
        !*params_in_out ||
        !in_out_len ||
        !tee_err ||
        !ta_err) {
        return -EINVAL;
    }

    return sel4_optee_invoke_ta(OPTEE_INVOKE,
                                ta_cmd,
                                params_in_out,
                                in_out_len,
                                tee_err,
                                ta_err);
}
