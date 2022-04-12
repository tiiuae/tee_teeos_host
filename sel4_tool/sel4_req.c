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

#define STORAGE_IMPORT_MSG_LEN  32752   /* 32kB - header - aligment */

typedef int sync_spinlock_t; /* seL4 spinlock */

/* memory structure in the beginning of crashlog area */
struct crashlog_hdr {
    struct circ_buf_hdr circ_hdr;
    sync_spinlock_t writer_lock;
    sync_spinlock_t reader_lock;
};


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

    if (!crashlog || !crashlog_len) {
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

int sel4_req_debug_config(int tee_fd, uint64_t *debug_flags)
{
    ssize_t ret;

    struct tty_msg tty = {0};

    struct ree_tee_config_cmd *ret_cmd = NULL;
    struct ree_tee_config_cmd cmd = {0};

    uint32_t cmd_len = sizeof(struct ree_tee_config_cmd);

    if (!debug_flags) {
        SEL4LOGE("ERROR params: %s: %d\n", __FUNCTION__, __LINE__);
        return -EINVAL;
    }

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

    ret = tty_req(tee_fd, &tty);
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

int sel4_open_comm()
{
    return sel4_open_tty();
}

void sel4_close_comm(int tee_fd)
{
    sel4_close_tty(tee_fd);
}

static int sel4_optee_invoke_ta(int tee_fd,
                                uint32_t optee_cmd,
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

    ret = tty_req(tee_fd, &tty);
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

static int sel4_optee_import_storage_partial(int tee_fd, uint8_t *import,
                                             uint32_t import_len,
                                             uint32_t storage_len)
{
    int ret = -1;

    uint32_t cmd_len = sizeof(struct ree_tee_optee_storage_cmd) + import_len;

    struct ree_tee_optee_storage_cmd cmd =
    {
        .hdr.msg_type = REE_TEE_OPTEE_IMPORT_STORAGE_REQ,
        .hdr.length = cmd_len,
        .storage.payload_len = import_len,
        .storage.storage_len = storage_len,
    };

    struct tty_msg tty = {
        .send = {
            {
                .buf = (void*)&cmd,
                .buf_len = sizeof(struct ree_tee_optee_storage_cmd)
            },
            {
                .buf = (char *)import,
                .buf_len = import_len,
            },
        },
        .recv_buf = NULL,
        .recv_len = HDR_LEN,
        .recv_msg = REE_TEE_OPTEE_IMPORT_STORAGE_RESP,
        .status_check = VERIFY_TEE_OK,
    };

    ret = tty_req(tee_fd, &tty);
    if (ret < 0)
        goto out;

    ret = 0;
out:
    free(tty.recv_buf);

    return ret;
}

static int optee_import_storage(int tee_fd, uint8_t *storage, uint32_t storage_len)
{
    int ret = -1;
    uint32_t pos = 0;
    uint32_t import_len = 0;

    do {
        import_len = MIN(storage_len - pos, STORAGE_IMPORT_MSG_LEN);

        ret = sel4_optee_import_storage_partial(tee_fd, 
                                                storage + pos,
                                                import_len,
                                                storage_len);
        if (ret) {
            return ret;
        }

        pos += import_len;

    } while (pos < storage_len);

    SEL4LOGI("%s:%d: import complete: %d\n", __FUNCTION__, __LINE__, pos);

    return 0;
}

static int sel4_optee_init_cmd(int tee_fd)
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

    ret = tty_req(tee_fd, &tty);
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

int sel4_optee_init(int tee_fd, uint8_t *storage, uint32_t storage_len)
{
    int ret = -1;

    if (storage && storage_len > 0) {
        SEL4LOGI("optee: import storage\n");
        ret = optee_import_storage(tee_fd, storage, storage_len);
        if (ret)
            return ret;
    } else {
        SEL4LOGI("optee: create an empty storage\n");
    }

    ret = sel4_optee_init_cmd(tee_fd);

    return ret;
}

int sel4_optee_open_session(int tee_fd, char **params_in_out, uint32_t *in_out_len,
                            int32_t *tee_err, uint32_t *ta_err)
{
    if (!params_in_out ||
        !*params_in_out ||
        !in_out_len ||
        !tee_err ||
        !ta_err) {
        return -EINVAL;
    }

    return sel4_optee_invoke_ta(tee_fd,
                                OPTEE_OPEN_SESSION,
                                TA_CMD_NA,
                                params_in_out,
                                in_out_len,
                                tee_err,
                                ta_err);
}

int sel4_optee_close_session(int tee_fd, char **params_in_out,
                             uint32_t *in_out_len, int32_t *tee_err,
                             uint32_t *ta_err)
{
    if (!params_in_out ||
        !*params_in_out ||
        !in_out_len ||
        !tee_err ||
        !ta_err) {
        return -EINVAL;
    }

    return sel4_optee_invoke_ta(tee_fd,
                                OPTEE_CLOSE_SESSION,
                                TA_CMD_NA,
                                params_in_out,
                                in_out_len,
                                tee_err,
                                ta_err);
}

int sel4_optee_invoke_cmd(int tee_fd, uint32_t ta_cmd, char **params_in_out,
                          uint32_t *in_out_len, int32_t *tee_err,
                          uint32_t *ta_err)
{
    if (!params_in_out ||
        !*params_in_out ||
        !in_out_len ||
        !tee_err ||
        !ta_err) {
        return -EINVAL;
    }

    return sel4_optee_invoke_ta(tee_fd,
                                OPTEE_INVOKE,
                                ta_cmd,
                                params_in_out,
                                in_out_len,
                                tee_err,
                                ta_err);
}

static int sel4_optee_export_storage_partial(int tee_fd, uint8_t **export,
                                             uint32_t *export_len,
                                             uint32_t *storage_len,
                                             uint32_t offset)
{
    int ret = -1;
    uint32_t payload_len = 0;

    struct ree_tee_optee_storage_cmd cmd = {
        .hdr.msg_type = REE_TEE_OPTEE_EXPORT_STORAGE_REQ,
        .hdr.length = sizeof(struct ree_tee_optee_storage_cmd),
        .storage.pos = offset,
    };

    struct ree_tee_optee_storage_cmd *resp = NULL;

    struct tty_msg tty = {
        .send = {{
            .buf = (void*)&cmd,
            .buf_len = cmd.hdr.length,
        },},
        .recv_buf = NULL,
        .recv_len = SKIP_LEN_CHECK,
        .recv_msg = REE_TEE_OPTEE_EXPORT_STORAGE_RESP,
        .status_check = VERIFY_TEE_OK,
    };

    ret = tty_req(tee_fd, &tty);
    if (ret < 0)
        goto out;

    if (ret < (ssize_t)sizeof(struct ree_tee_optee_storage_cmd)) {
        SEL4LOGE("%s:%d: ERROR: Invalid msg size: %d\n", __FUNCTION__, __LINE__, ret);
        ret = -EINVAL;
        goto out;
    }

    resp = (struct ree_tee_optee_storage_cmd *)tty.recv_buf;
    payload_len = resp->storage.payload_len;

    SEL4LOGI("%s: offset: %d, payload_len: %d, storage_len: %d\n", __FUNCTION__,
        offset, payload_len, resp->storage.storage_len);

    *export = malloc(payload_len);
    if (!*export) {
        SEL4LOGE("%s:%d: ERROR: out of memory\n", __FUNCTION__, __LINE__);
        ret = -ENOMEM;
        goto out;
    }

    memcpy(*export, resp->storage.payload, payload_len);
    *export_len = payload_len;
    *storage_len = resp->storage.storage_len;

    ret = 0;
out:
    free(tty.recv_buf);

    return ret;
}

int sel4_optee_export_storage(int tee_fd, uint8_t **storage, uint32_t *storage_len)
{
    int ret = -1;
    uint8_t *recv_buf = NULL;
    uint8_t *partial = NULL;
    uint32_t len = 0;
    uint32_t export_len = 0;
    uint32_t offset = 0;

    if (!storage || !storage_len) {
        SEL4LOGE("%s:%d: ERROR: params\n", __FUNCTION__, __LINE__);
        return -EINVAL;
    }

    do {
        ret = sel4_optee_export_storage_partial(tee_fd,
                                                &partial,
                                                &len,
                                                &export_len,
                                                offset);
        if (ret) {
            goto err_out;
        }

        recv_buf = realloc(recv_buf, offset + len);
        if (!recv_buf)
        {
            SEL4LOGE("%s:%d: ERROR: out of memory\n", __FUNCTION__, __LINE__);
            ret = -ENOMEM;
            goto err_out;
        }

        memcpy(recv_buf + offset, partial, len);

        offset += len;

        free(partial);
        partial = NULL;

    } while (offset < export_len);

    if (offset != export_len) {
        SEL4LOGE("%s:%d: ERROR: invalid storage size: %d / %d\n", __FUNCTION__, __LINE__,
            offset, export_len);
        ret = -EFAULT;
        goto err_out;
    }

    *storage = recv_buf;
    *storage_len = export_len;

    return 0;

err_out:
    free(partial);
    free(recv_buf);

    return ret;
}