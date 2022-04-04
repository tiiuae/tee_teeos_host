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

#define SECURE 0
#define PLAIN  1

static uint8_t tmp_key[] = {0x76, 0xa4, 0x58, 0xd1, 0x0e, 0xd7, 0xc0, 0x9b, 0xf5, 0x0d, 0xd2, 0xb9};

static uint8_t test_data[] = {
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xFF
};

static uint8_t tmp_hash [] = {
0x74, 0xf0, 0xdb, 0x99, 0x7d, 0xd3, 0x5a, 0xe9, 0x65, 0xab, 0x39, 0x74, 0x2e, 0x76, 0xf9, 0x30,
0x20, 0x74, 0x11, 0xe5, 0xc6, 0x74, 0x26, 0x2f, 0xe4, 0xcc, 0xae, 0x53, 0xec, 0x0c, 0x2f, 0xac,
0x65, 0x24, 0xd0, 0x41, 0x9a, 0x34, 0x2b, 0x60, 0xb6, 0x76, 0xc0, 0x03, 0xaa, 0x2d, 0xf9, 0xbb
};

static void hexdump(void* data, size_t size)
{
    char ascii[17] = { 0 };

    for (unsigned int i = 0; i < size; ++i)
    {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~')
            ascii[i % 16] = ((unsigned char*)data)[i];
        else
            ascii[i % 16] = '.';

        if ((i+1) % 8 != 0 &&
            i+1 != size)
            continue;

        printf(" ");
        if ((i+1) % 16 == 0)
            printf("|  %s \n", ascii);
        else if (i+1 == size)
        {
            ascii[(i+1) % 16] = '\0';
            if ((i+1) % 16 <= 8)
                printf(" ");
            for (int j = (i+1) % 16; j < 16; ++j)
                printf("   ");
            printf("|  %s \n", ascii);
        }
    }
}

static void print_menu(void)
{
    printf("\n\nBuild Date %s Time %s", __DATE__, __TIME__);
    printf("\n\nWelcome seL4 test application\n");
    printf("Select:\n");
    printf("0 - Exit\n");
    printf("1 - Random number from sel4 TEE\n");
    printf("2 - Write data to sNVM\n");
    printf("3 - Read Data from sNVM\n");
    printf("4 - Device serial number\n");
    printf("5 - PUF demo\n");
    printf("6 - seL4 status\n");
    printf("7 - Unknown msg type\n");
    printf("8 - Sign Service\n");
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

static int handle_snvm_write(uint8_t *input_data, uint8_t *key, int page, int mode)
{
    ssize_t ret;
    struct ree_tee_snvm_cmd cmd = {
        .hdr.msg_type = REE_TEE_SNVM_WRITE_REQ,
        .hdr.length = sizeof(struct ree_tee_snvm_cmd),
    };

    struct tty_msg tty = {
        .send = {{
            .buf = (void*)&cmd,
            .buf_len = cmd.hdr.length
        },},
        .recv_buf = NULL,
        .recv_len = HDR_LEN,
        .recv_msg = REE_TEE_SNVM_WRITE_RESP,
        .status_check = VERIFY_TEE_OK,
    };

    struct ree_tee_snvm_cmd *resp = NULL;

    /* Open binary file for input data*/
    if((!input_data) || (!key)){
        return -EINVAL;
    }

    /*
     * Length here means how much we are goint to write data, for secure
     * write we send 236 bytes and for plaintext 252 bytes
     */
    if (mode == PLAIN) {
        cmd.snvm_length = 252;
    } else if (mode == SECURE) {
        cmd.snvm_length = 236;
    } else {
        printf("Invalid mode\n");
        return -EINVAL;
    }
    cmd.page_number = page;
    memcpy(cmd.user_key, key, USER_KEY_LENGTH );
    memcpy(cmd.data, input_data, cmd.snvm_length);

    ret = tty_req(&tty);
    if (ret < 0)
    {
        printf("snvm write failed: %ld\n", ret);
        goto out;
    }

    resp = (struct ree_tee_snvm_cmd*)tty.recv_buf;

    printf("msg status: %d\n", resp->hdr.status);

    ret = 0;

out:
    if (tty.recv_buf) {
        free(tty.recv_buf);
    }

    return ret;
}

static int handle_snvm_read(int page, uint8_t *key, uint8_t *output, int mode)
{

    ssize_t ret;
    struct ree_tee_snvm_cmd cmd = {
        .hdr.msg_type = REE_TEE_SNVM_READ_REQ,
        .hdr.length = sizeof(struct ree_tee_snvm_cmd),
    };

    struct tty_msg tty = {
        .send = {{
            .buf = (void*)&cmd,
            .buf_len = cmd.hdr.length
        },},
        .recv_buf = NULL,
        .recv_len = sizeof(cmd),
        .recv_msg = REE_TEE_SNVM_READ_RESP,
        .status_check = VERIFY_TEE_OK,
    };

    struct ree_tee_snvm_cmd *resp = NULL;

    /*
     * Length here means how much we are goint to read data, for secure
     * read we request 236 bytes and for plaintext 252 bytes
     */
    if (mode == PLAIN) {
        cmd.snvm_length = 252;
    } else if (mode == SECURE) {
        cmd.snvm_length = 236;
    } else {
        printf("Invalid mode\n");
        return -EINVAL;
    }
    cmd.page_number = page;
    memcpy(cmd.user_key, key, USER_KEY_LENGTH );

    ret = tty_req(&tty);
    if (ret < 0)
    {
        printf("snvm read failed: %ld\n", ret);
        goto out;
    }

    resp = (struct ree_tee_snvm_cmd*)tty.recv_buf;

    if (output)
    {
        /* response data buffer is 252 bytes but actual data can be 236 or 252 bytes */
        memcpy(output, resp->data, resp->snvm_length);
    }
    else
    {
        printf("\nsNVM page %d data:", page);
        for(unsigned int i = 0; i < resp->snvm_length; i++) {
            printf("%2.2x ", resp->data[i]);
        }
    }

    ret = 0;
out:
    if (tty.recv_buf) {
        free(tty.recv_buf);
    }

    return ret;
}

static int handle_puf_request(uint8_t opcode, uint8_t *challenge, uint8_t *output)
{
    ssize_t ret;
    struct ree_tee_puf_cmd cmd = {
        .hdr.msg_type = REE_TEE_PUF_REQ,
        .hdr.length = sizeof(struct ree_tee_puf_cmd),
        .opcode = opcode,
    };

    struct tty_msg tty = {
        .send = {{
            .buf = (void*)&cmd,
            .buf_len = cmd.hdr.length
        },},
        .recv_buf = NULL,
        .recv_len = sizeof(cmd),
        .recv_msg = REE_TEE_PUF_RESP,
        .status_check = VERIFY_TEE_OK,
    };

    struct ree_tee_puf_cmd *resp = NULL;

    memcpy(cmd.request, challenge, PUF_CHALLENGE );

    ret = tty_req(&tty);
    if (ret < 0)
    {
        printf("puf response failed: %ld\n", ret);
        goto out;
    }

    resp = (struct ree_tee_puf_cmd*)tty.recv_buf;

    if (output)
    {
        memcpy(output, resp->response, PUF_RESPONSE);
    }
    else
    {
        printf("\nPUF data:\n");
        hexdump(resp->response, PUF_RESPONSE);
    }

    ret = 0;

out:
    if (tty.recv_buf) {
        free(tty.recv_buf);
    }

    return ret;
}

static int handle_sign_request(uint8_t format, uint8_t *hash, uint8_t *output)
{
    ssize_t ret;
    struct ree_tee_sign_cmd cmd = {
        .hdr.msg_type = REE_TEE_SIGN_REQ,
        .hdr.length = sizeof(struct ree_tee_sign_cmd),
        .format = format,
    };

    struct tty_msg tty = {
        .send = {{
            .buf = (void*)&cmd,
            .buf_len = cmd.hdr.length
        },},
        .recv_buf = NULL,
        .recv_len = sizeof(cmd),
        .recv_msg = REE_TEE_SIGN_RESP,
        .status_check = VERIFY_TEE_OK,
    };

    struct ree_tee_sign_cmd *resp = NULL;

    memcpy(cmd.hash, hash, HASH_LENGTH );

    ret = tty_req(&tty);
    if (ret < 0)
    {
        printf("sign request failed: %ld\n", ret);
        goto out;
    }

    resp = (struct ree_tee_sign_cmd*)tty.recv_buf;

    if (output)
    {
        memcpy(output, resp->response, SIGN_RESP_LENGTH);
    }
    else
    {
        printf("\nSigned data:\n");
        hexdump(resp->response, SIGN_RESP_LENGTH);
    }

    ret = 0;
out:
    if (tty.recv_buf) {
        free(tty.recv_buf);
    }

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

static int handle_publick_key_extraction_request(struct key_data_blob *input_blob, uint32_t blob_size, uint32_t *nbits, uint8_t **output, uint32_t *pubkey_len)
{
    ssize_t ret;

    struct tty_msg tty = {0};

    struct ree_tee_pub_key_resp_cmd *ret_cmd = NULL;
    struct ree_tee_pub_key_req_cmd *cmd = NULL;

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

    cmd->hdr.msg_type = REE_TEE_EXT_PUBKEY_REQ;
    cmd->hdr.length = cmd_len;


    memcpy(&cmd->data_in, input_blob, blob_size);

    tty.send[0].buf = (void*)cmd,
    tty.send[0].buf_len = cmd->hdr.length,
    tty.recv_buf = NULL;
    tty.recv_len = SKIP_LEN_CHECK;
    tty.recv_msg = REE_TEE_EXT_PUBKEY_RESP;
    tty.status_check = VERIFY_TEE_OK;

    ret = tty_req(&tty);
    if (ret < 0)
        goto out;

    ret_cmd = (struct ree_tee_pub_key_resp_cmd*)tty.recv_buf;

    if (ret < (ssize_t)sizeof(struct ree_tee_pub_key_resp_cmd))
    {
        printf("Invalid msg size: %ld, type: %d, status: %d, hdr_len: %d\n",
               ret, ret_cmd->hdr.msg_type, ret_cmd->hdr.status,
               ret_cmd->hdr.length);

        ret = -EINVAL;
        goto out;
    }

    printf("Publick key data Name = %s Length = %d\n", ret_cmd->key_info.name, ret_cmd->key_info.pubkey_length);

    if (output) {
        *output = malloc(ret_cmd->key_info.pubkey_length);
        if (!*output)
        {
            printf("Out of memory: %s: %d\n", __FUNCTION__, __LINE__);
            ret = -ENOMEM;
            goto out;
        }
        memcpy(*output, &ret_cmd->pubkey, ret_cmd->key_info.pubkey_length);
        *nbits = ret_cmd->key_info.key_nbits;
        *pubkey_len = ret_cmd->key_info.pubkey_length;
    } else {
        uint8_t *public_key = &ret_cmd->pubkey[0];
        printf("PubKey\n");
        hexdump(public_key, ret_cmd->key_info.pubkey_length);

        printf("Key data GUID:\n");
        hexdump(&ret_cmd->key_info.guid, 32);
    }

    ret = 0;

out:
    if (cmd)
        free(cmd);

    return ret;
}


static int cmdline(int argc, char* argv[])
{
    int ret = -1;

    char *in_file = NULL;
    char *out_file = NULL;
    uint32_t tool_cmd = TOOL_CMD_INVALID;

    uint32_t format = 0;
    struct key_data_blob *blob = NULL;
    uint32_t blob_size = 0;
    uint8_t *pubkey_bin = NULL;
    uint32_t len = 0;
    uint32_t nbits = 0;
    uint64_t debug_flags = 0;
    char *crashlog = NULL;

    ret = sel4_tool_parse_opts(argc, argv, &in_file, &out_file, &tool_cmd, &debug_flags);
    if (ret)
        goto out;

    switch (tool_cmd)
    {
    case TOOL_CMD_GENERATE_RSA_CIPHERED:
        format = KEY_RSA_CIPHERED;
        /* fallthrough */
    case TOOL_CMD_GENERATE_RSA_PLAINTEXT:
        if (format != KEY_RSA_CIPHERED)
            format = KEY_RSA_PLAINTEXT;

        printf("TOOL_CMD_GENERATE_KEYS, format: %d\n", format);
        if (!out_file)
        {
            printf("ERROR no out file defined\n");
            ret = -EINVAL;
            goto out;
        }

        printf("out_file: %s\n", out_file);

        ret = sel4_req_key_creation(format,
                                    2048,
                                    0xEEEEEEEE,
                                    "Kekkonen",
                                    &blob,
                                    &blob_size);
        if (ret)
            goto out;

        printf("Key data GUID:\n");
        hexdump(blob->key_data_info.guid, 32);

        if (blob->key_data_info.format == KEY_RSA_PLAINTEXT)
        {
            printf("PubKey\n");
            hexdump(&blob->key_data.keys[0], blob->key_data_info.pubkey_length);

            printf("PrivateKey\n");
            hexdump(&blob->key_data.keys[blob->key_data_info.pubkey_length], blob->key_data_info.privkey_length);
        }
        else
        {
            printf("Key data ciphered\n");
            printf("Storage blob\n");
            hexdump(blob, blob_size);
        }

        ret = sel4_tool_save_file(out_file, (uint8_t *)blob, blob_size);
        goto out;

    case TOOL_CMD_EXPORT_KEY:
    {
        printf("TOOL_CMD_EXPORT_KEY\n");
        if (!in_file)
        {
            printf("ERROR no in file defined\n");
            ret = -EINVAL;
            goto out;
        }

        if (!out_file)
        {
            printf("ERROR no out file defined\n");
            ret = -EINVAL;
            goto out;
        }

        printf("in_file: %s\n", in_file);
        printf("out_file: %s\n", out_file);

        ret = sel4_tool_load_file(in_file, (uint8_t **)&blob, &blob_size);
        if (ret)
            goto out;

        struct key_data_blob *input = (struct key_data_blob*)blob;
        ret = handle_publick_key_extraction_request(input,
                                                    blob_size,
                                                    &nbits,
                                                    &pubkey_bin,
                                                    &len);
        if (ret)
            goto out;

        printf("pubkey_bin\n");
        hexdump(pubkey_bin, len);

        ret = sel4_tool_save_file(out_file, pubkey_bin, len);
    }
    break;
    case TOOL_CMD_GENERATE_ECC:
    {
        format = KEY_ECC_KEYPAIR;
        printf("TOOL_CMD_GENERATE_KEYS, format: %d\n", format);
        if (!out_file)
        {
            printf("ERROR no out file defined\n");
            ret = -EINVAL;
            goto out;
        }

        printf("out_file: %s\n", out_file);

        ret = sel4_req_key_creation(format,
                                    256,
                                    0xEEEEEEEE,
                                    "ECC_keys",
                                    &blob,
                                    &blob_size);
        if (ret)
            goto out;

        printf("Key data GUID:\n");
        hexdump(blob->key_data_info.guid, 32);

        printf("PubKey\n");
        hexdump(&blob->key_data.keys[0], blob->key_data_info.pubkey_length);

        printf("PrivateKey\n");
        hexdump(&blob->key_data.keys[blob->key_data_info.pubkey_length], blob->key_data_info.privkey_length);

        ret = sel4_tool_save_file(out_file, (uint8_t *)blob, blob_size);
        goto out;

    }
    break;
    case TOOL_CMD_DEBUG_FLAGS:
    {
        printf("Debug flags  0x%lx \n", debug_flags);
        ret = sel4_req_debug_config(&debug_flags);
    }
    break;
    case TOOL_CMD_GENERATE_X25519:
    {
        format = KEY_X25519_KEYPAIR;
        printf("TOOL_CMD_GENERATE_KEYS, format: %d\n", format);
        if (!out_file)
        {
            printf("ERROR no out file defined\n");
            ret = -EINVAL;
            goto out;
        }

        printf("out_file: %s\n", out_file);

        ret = sel4_req_key_creation(format,
                                    1, /* public key x509 format*/
                                    0xEEEEEEEE,
                                    "X25519_keys",
                                    &blob,
                                    &blob_size);
        if (ret)
            goto out;

        printf("Key data GUID:\n");
        hexdump(blob->key_data_info.guid, 32);

        printf("PubKey\n");
        hexdump(&blob->key_data.keys[0], blob->key_data_info.pubkey_length);

        printf("PrivateKey\n");
        hexdump(&blob->key_data.keys[blob->key_data_info.pubkey_length], blob->key_data_info.privkey_length);

        ret = sel4_tool_save_file(out_file, (uint8_t *)blob, blob_size);
        goto out;

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
    case TOOL_CMD_IMPORT_KEY:
    {
        printf("TOOL_CMD_IMPORT_KEY\n");
        if (!in_file)
        {
            printf("ERROR no in file defined\n");
            ret = -EINVAL;
            goto out;
        }
        printf("in_file: %s\n", in_file);

        ret = sel4_tool_load_file(in_file, (uint8_t **)&blob, &blob_size);
        if (ret)
            goto out;

        struct key_data_blob *input = (struct key_data_blob*)blob;

        printf("Import Keys \n");
        ret = sel4_req_key_import(input, blob_size);

        if (ret)
            printf("Key file imported to tee-os\n");
        else
            printf("Key file import failed %d\n", ret);
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
    case TOOL_CMD_TEST_CHANGE_CLID:
        /* update keyinfo client id which is different than inside the blob */
        printf("TOOL_CMD_TEST_CHANGE_CLID\n");

        if (!in_file)
        {
            printf("ERROR no in file defined\n");
            ret = -EINVAL;
            goto out;
        }

        if (!out_file)
        {
            printf("ERROR no out file defined\n");
            ret = -EINVAL;
            goto out;
        }

        ret = sel4_tool_load_file(in_file, (uint8_t **)&blob, &blob_size);
        if (ret)
            goto out;

        printf("blob->key_data_info.client_id %d -> ", blob->key_data_info.client_id);
        blob->key_data_info.client_id += 5;
        printf("%d\n", blob->key_data_info.client_id);

        ret = sel4_tool_save_file(out_file, (uint8_t *)blob, blob_size);
        break;

    case TOOL_CMD_OPTEE_INIT:
        ret = sel4_optee_init();
        break;
    default:
        printf("ERROR: unknown cmd: %d\n", tool_cmd);
        break;
    }

out:
    free(in_file);
    free(out_file);
    free(blob);
    free(pubkey_bin);
    free(crashlog);

    return ret;
}

int main(int argc, char* argv[])
{
    int choice;
    int i = 1;
    int page = 0;
    int ret = 0;
    int mode = 0;

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
            printf("\nEnter page to write: ");
            ret = scanf("%d", &page);
            printf("\nEnter mode (1 PLAIN, 0 SECURE): ");
            ret = scanf("%d", &mode);
            ret = handle_snvm_write(test_data, tmp_key, page, mode);
        break;
        case 3:
            printf("\nEnter page to read: ");
	        ret = scanf("%d", &page);
            printf("\nEnter mode (1 PLAIN, 0 SECURE): ");
            ret = scanf("%d", &mode);
            ret = handle_snvm_read(page, tmp_key, NULL, mode);
        break;
        case 4:
            ret = handle_deviceid_request(NULL);
        break;
        case 5:
        {
            uint8_t puf_challenge[PUF_CHALLENGE];
            printf("\nEnter opcode for PUF: ");
	        ret = scanf("%d", &page);
            /*set device serial as puf challenge*/
            ret = handle_deviceid_request(puf_challenge);
            if (ret)
            {
                printf("ERROR handle_deviceid_request: %d", ret);
                break;
            }

            ret = handle_puf_request(page, puf_challenge, NULL);

        }
        break;
        case 6:
            ret = handle_status_request();
        break;
        case 7:
            ret = handle_unknown_request();
        break;
        case 8:
        {
            int format;
            printf("\nEnter format (1 RAW, 0 DER): ");
            ret = scanf("%d", &format);
            if (format)
                ret = handle_sign_request(RAW_FORMAT, tmp_hash, NULL);
            else
                ret = handle_sign_request(DER_FORMAT, tmp_hash, NULL);
        }
        break;
        default:
        break;
        }
    }

    return ret;
}
