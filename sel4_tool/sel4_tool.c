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
#include "ree_tee_msg.h"
#include "sel4_tty_rpmsg.h"
#include "sel4_tool_cmdline.h"
#include "sel4_req.h"


static void print_menu(void)
{
    printf("\n\nBuild Date %s Time %s", __DATE__, __TIME__);
    printf("\n\nWelcome seL4 test application\n");
    printf("Select:\n");
    printf("0 - Exit\n");
    printf("1 - Random number from sel4 TEE\n");
    printf("2 - Device serial number\n");
    printf("3 - seL4 status\n");
    printf("4 - Unknown msg type\n");
    printf("\n");
}

static int handle_unknown_request(void)
{
    ssize_t ret;

    int32_t invalid_type = REE_TEE_INVALID - 2;

    struct ree_tee_status_req cmd = {
        .hdr.msg_type = invalid_type,
        .hdr.length = HDR_LEN,
    };

    struct tty_msg tty = {
        .send = {{
            .buf = (void*)&cmd,
            .buf_len = cmd.hdr.length
        },},
        .recv_buf = NULL,
        .recv_len = HDR_LEN,
        .recv_msg = invalid_type, /* expect to get invalid msg type also in response */
        .status_check = SKIP_TEE_OK_CHECK,
    };

    struct ree_tee_status_resp *resp = NULL;

    ret = tty_req(&tty);
    if (ret < 0)
    {
        printf("Message failed: %ld \n", ret);
        goto out;
    }

    resp = (struct ree_tee_status_resp*)tty.recv_buf;

    if (resp->hdr.status != TEE_UNKNOWN_MSG)
    {
        printf("ERROR invalid error code: %d\n", resp->hdr.status);
        ret = -EFAULT;
        goto out;
    }

    printf("msg type: %d, status: %d\n", resp->hdr.msg_type, resp->hdr.status);

    ret = 0;
out:
    free(tty.recv_buf);

    return ret;
}

static int handle_invalid_msg_len(int32_t send_len, uint32_t recv_len, uint32_t recv_status)
{
    ssize_t ret;

    struct ree_tee_status_req cmd = {
        .hdr.msg_type = REE_TEE_STATUS_REQ,
        .hdr.length = send_len,
    };

    struct tty_msg tty = {
        .send = {{
            .buf = (void*)&cmd,
            .buf_len = cmd.hdr.length
        },},
        .recv_buf = NULL,
        .recv_len = recv_len,
        .recv_msg = REE_TEE_STATUS_RESP,
        .status_check = SKIP_TEE_OK_CHECK,
    };

    struct ree_tee_status_resp *resp = NULL;

    ret = tty_req(&tty);
    if (ret < 0)
    {
        printf("Message failed: %ld \n", ret);
        goto out;
    }

    resp = (struct ree_tee_status_resp*)tty.recv_buf;

    if (resp->hdr.status != (int32_t)recv_status)
    {
        printf("ERROR invalid error code: %d\n", resp->hdr.status);
        ret = -EFAULT;
        goto out;
    }

    printf("msg type: %d, status: %d\n", resp->hdr.msg_type, resp->hdr.status);

    ret = 0;
out:
    free(tty.recv_buf);

    return ret;
}

static int handle_status_request(void)
{
    ssize_t ret;

    struct ree_tee_status_req cmd = {
        .hdr.msg_type = REE_TEE_STATUS_REQ,
        .hdr.length = HDR_LEN,
    };

    struct tty_msg tty = {
        .send = {{
            .buf = (void*)&cmd,
            .buf_len = cmd.hdr.length
        },},
        .recv_buf = NULL,
        .recv_len = HDR_LEN,
        .recv_msg = REE_TEE_STATUS_RESP,
        .status_check = VERIFY_TEE_OK,
    };

    struct ree_tee_status_resp *resp = NULL;

    ret = tty_req(&tty);
    if (ret < 0)
    {
        printf("Status message failed: %ld \n", ret);
        goto out;
    }

    resp = (struct ree_tee_status_resp*)tty.recv_buf;

    printf("msg status: %d\n", resp->hdr.status);

    ret = 0;

out:
    free(tty.recv_buf);

    return ret;
}

static int handle_deviceid_request(uint8_t *output)
{
    ssize_t ret = -1;
    struct ree_tee_deviceid_cmd cmd ={
        .hdr.msg_type = REE_TEE_DEVICEID_REQ,
        .hdr.length = HDR_LEN,
    };

    struct tty_msg tty = {
        .send = {{
            .buf = (void*)&cmd,
            .buf_len = cmd.hdr.length
        },},
        .recv_buf = NULL,
        .recv_len = sizeof(cmd),
        .recv_msg = REE_TEE_DEVICEID_RESP,
        .status_check = VERIFY_TEE_OK,
    };

    struct ree_tee_deviceid_cmd *resp = NULL;

    ret = tty_req(&tty);
    if (ret < 0)
    {
        printf("device id failed: %ld\n", ret);
        goto out;
    }

    resp = (struct ree_tee_deviceid_cmd *)tty.recv_buf;

    if (output)
    {
        memcpy(output, resp->response, DEVICE_ID_LENGTH);
    }
    else
    {
        /* print value*/
        printf("\nDeviceID: ");
        for(int i = 0; i < DEVICE_ID_LENGTH; i++) {
            printf("%2.2x", resp->response[i]);
        }
    }

    ret = 0;
out:
    if (tty.recv_buf) {
        free(tty.recv_buf);
    }

    return ret;
}

static int handle_rng_request(uint8_t *output)
{
    ssize_t ret;

    struct ree_tee_rng_cmd cmd ={
        .hdr.msg_type = REE_TEE_RNG_REQ,
        .hdr.length = HDR_LEN,
    };

    struct tty_msg tty = {
        .send = {{
            .buf = (void*)&cmd,
            .buf_len = cmd.hdr.length
        },},
        .recv_buf = NULL,
        .recv_len = sizeof(cmd),
        .recv_msg = REE_TEE_RNG_RESP,
        .status_check = VERIFY_TEE_OK,
    };

    struct ree_tee_rng_cmd *resp = NULL;

    ret = tty_req(&tty);
    if (ret < 0) {
        printf("rng request failed: %ld\n", ret);
        goto out;
    }

    resp = (struct ree_tee_rng_cmd *)tty.recv_buf;


    if (output)
    {
        memcpy(output, resp->response, RNG_SIZE_IN_BYTES);
    }
    else
    {
        /* print value*/
        printf("\nRNG value:");
        for(int i = 0; i < RNG_SIZE_IN_BYTES; i++) {
            printf("%2.2x ", resp->response[i]);
        }
    }

    ret = 0;
out:
    if (tty.recv_buf) {
        free(tty.recv_buf);
    }

    return ret;
}

static int cmdline(int argc, char* argv[])
{
    int ret = -1;

    char *in_file = NULL;
    char *out_file = NULL;
    uint32_t tool_cmd = TOOL_CMD_INVALID;
    uint8_t *memory_buffer = NULL;
    uint32_t len = 0;
    uint64_t debug_flags = 0;
    char *crashlog = NULL;

    ret = sel4_tool_parse_opts(argc, argv, &in_file, &out_file, &tool_cmd, &debug_flags);
    if (ret)
        goto out;

    switch (tool_cmd)
    {
    case TOOL_CMD_DEBUG_FLAGS:
    {
        printf("Debug flags  0x%lx \n", debug_flags);
        ret = sel4_req_debug_config(&debug_flags);
    }
    break;
    case TOOL_CMD_READ_CRASHLOG:
        ret = sel4_read_crashlog(&crashlog, &len);
        if (ret) {
            goto out;
        }

        ret = sel4_tool_save_file(out_file, (uint8_t *)crashlog, len);
        if (ret) {
            goto out;
        }

        break;
    case TOOL_CMD_TEST_STATUS:
        printf("TOOL_CMD_TEST_STATUS\n");
        ret = handle_status_request();
        break;
    case TOOL_CMD_TEST_UNKNOWN_CMD:
        printf("TOOL_CMD_TEST_UNKNOWN_CMD\n");
        ret = handle_unknown_request();
        break;
    case TOOL_CMD_TEST_INV_SEND_LEN:
        printf("TOOL_CMD_TEST_INV_SEND_LEN\n");
        ret = handle_invalid_msg_len(HDR_LEN - 3, HDR_LEN, TEE_INVALID_MSG_SIZE);
        break;
    case TOOL_CMD_TEST_INV_RECV_LEN:
        printf("TOOL_CMD_TEST_INV_RECV_LEN\n");
        ret = handle_invalid_msg_len(HDR_LEN, HDR_LEN - 3, TEE_OK);
        break;
    case TOOL_CMD_OPTEE_INIT:
        if (in_file)
        {
            printf("Import secure storage\n");
            ret = sel4_tool_load_file(in_file, &memory_buffer, &len);
            if (ret)
                goto out;
        }

        ret = sel4_optee_init(memory_buffer, len);
        break;

    case TOOL_CMD_OPTEE_EXPORT_STORAGE:
        if (!out_file)
        {
            printf("ERROR no out file defined\n");
            ret = -EINVAL;
            goto out;
        }

        ret = sel4_optee_export_storage(&memory_buffer, &len);
        if (ret)
            goto out;

        ret = sel4_tool_save_file(out_file, memory_buffer, len);
        if (ret)
            goto out;

        printf("Exported OPTEE storage %d bytes\n", len);

        break;
    default:
        printf("ERROR: unknown cmd: %d\n", tool_cmd);
        break;
    }

out:
    free(in_file);
    free(out_file);
    free(memory_buffer);
    free(crashlog);

    return ret;
}

int main(int argc, char* argv[])
{
    int choice;
    int i = 1;
    int ret = 0;

    if (argc > 1)
    {
        ret = cmdline(argc, argv);
        return ret;
    }

    while (i)
    {
        print_menu();
        ret = scanf("%d", &choice);

        switch (choice)
        {
        case 0:
            i = 0;
            break;
        case 1:
            ret = handle_rng_request(NULL);
            break;
        case 2:
            ret = handle_deviceid_request(NULL);
        break;
        case 3:
            ret = handle_status_request();
        break;
        case 4:
            ret = handle_unknown_request();
        break;
        default:
        break;
        }
    }

    return ret;
}
