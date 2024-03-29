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
#include <termios.h>
#include <stdlib.h>
#include <poll.h>

#include "ree_tee_msg.h"
#include "sel4_tty_rpmsg.h"

#include "sel4_log.h"

#define SEL4TTY "/dev/ttyRPMSG6"

int sel4_open_tty()
{
    int fd = 0;
    struct termios tty = {0};
    int err = -1;

    struct flock file_lock = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0,
    };

    fd = open(SEL4TTY, O_RDWR | O_NOCTTY);
    if(fd <= 0)
    {
        SEL4LOGE("failed to open %s: %d\n", SEL4TTY, errno);
        return -errno;
    }

    /* try to lock tty file */
    err = fcntl(fd, F_OFD_SETLK, &file_lock);
    if (err) {
        SEL4LOGE("fcntl error: %d\n", errno);
        return -errno;
    }

    /* From https://github.com/polarfire-soc/polarfire-soc-linux-examples/
     *                                       amp/rpmsg-tty-example/rpmsg-tty.c
     */
    tcgetattr(fd, &tty);              /* get current attributes */
    cfmakeraw(&tty);                  /* raw input */
    tty.c_cc[VMIN] = 0;               /* non blocking */
    tty.c_cc[VTIME] = 0;              /* non blocking */
    tcsetattr(fd, TCSANOW, &tty);     /* write attributes */

    return fd;
}

void sel4_close_tty(int fd)
{
    int err = -1;

    struct flock file_unlock = {
        .l_type = F_UNLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0,

    };

    if (fd < 1) {
        SEL4LOGE("invalid file: %d\n", fd);
        return;
    }

    /* release tty file lock */
    err = fcntl(fd, F_OFD_SETLK, &file_unlock);
    /* execute close() even if fcntl fails */
    if (err) {
        SEL4LOGE("fcntl error: %d\n", errno);
    }

    close(fd);
}

static int tty_read_resp(int tty_fd, struct tty_msg *tty)
{
    int err = -1;
    ssize_t read_bytes = 0;
    ssize_t recv = 0;
    ssize_t msg_len = 0;

    struct pollfd fds = {
        .fd = tty_fd,
        .events = POLLIN,
    };

    struct ree_tee_hdr recv_hdr = { 0 };

    /* Wait until data available in TTY */
    err = poll(&fds, 1, -1);
    if (err < 1)
    {
        SEL4LOGE("ERROR: poll: %d\n", errno);
        err = -EACCES;
        goto err_out;
    }

    /* read header to allocate buffer for whole message */
    recv = read(tty_fd, &recv_hdr, HDR_LEN);
    if (recv != HDR_LEN)
    {
        SEL4LOGE("ERROR: read hdr: %ld (%d)\n", recv, errno);
        err = -EIO;
        goto err_out;
    }

    SEL4LOGI("%s: reply len: %d\n", __FUNCTION__, recv_hdr.length);

    tty->recv_buf = malloc(recv_hdr.length);
    if (!tty->recv_buf)
    {
        SEL4LOGE("ERROR: out of memory: %d\n", __LINE__);
        err = -ENOMEM;
        goto err_out;
    }

    msg_len = recv_hdr.length;
    read_bytes += recv;

    memcpy(tty->recv_buf, &recv_hdr, HDR_LEN);

    while (read_bytes != msg_len) {
        recv = read(tty_fd, tty->recv_buf + read_bytes, msg_len - read_bytes);

        if (recv < 0)
        {
            SEL4LOGE("ERROR: read: %d, read_bytes: %ld\n", errno, read_bytes);
            err = -EBUSY;
            goto err_out;
        }

        read_bytes += recv;
    }

    return read_bytes;

err_out:
    if (tty->recv_buf)
    {
        free(tty->recv_buf);
        tty->recv_buf = NULL;
    }

    return err;
}

int tty_req(int tty_fd, struct tty_msg *tty)
{
    ssize_t ret = -1;

    struct ree_tee_hdr *hdr = NULL;

    if (tty_fd < 1 || !tty) {
        SEL4LOGE("ERROR: invalid parameters\n");
        return -EINVAL;
    }


    for (int i = 0; i < TTY_SEND_BUF_COUNT; i++) {
        /* skip empty buffers */
        if (tty->send[i].buf_len == 0 || !tty->send[i].buf) {
            SEL4LOGI("%s: tty req[%d]: buffer empty\n", __FUNCTION__, i);
            continue;
        }

        SEL4LOGI("%s: tty req[%d], len: %ld\n", __FUNCTION__, i, tty->send[i].buf_len);

        /*Write message to TEE*/
        ret = write(tty_fd, tty->send[i].buf, tty->send[i].buf_len);

        if (ret != (ssize_t)tty->send[i].buf_len)
        {
            SEL4LOGE("Writing request failed (%d), (%ld / %ld)\n", errno, ret, tty->send[i].buf_len);
            ret = -EIO;
            goto err_out;
        }
    }

    /* Recv TEE reply */
    ret = tty_read_resp(tty_fd, tty);
    if (ret < 0)
    {
        goto err_out;
    }

    hdr = (struct ree_tee_hdr *)tty->recv_buf;

    if (tty->status_check == VERIFY_TEE_OK &&
        hdr->status != TEE_OK)
    {
        SEL4LOGE("ERROR: header status: %d\n", hdr->status);
        ret = -EFAULT;
        goto err_out;
    }

    if (tty->recv_len != SKIP_LEN_CHECK &&
        tty->recv_len != ret)
    {
        SEL4LOGE("ERROR: invalid msg len: %ld (%d)\n", ret, tty->recv_len);
        ret = -EFAULT;
        goto err_out;
    }

    if (tty->recv_msg != REE_TEE_INVALID &&
        tty->recv_msg != hdr->msg_type)
    {
        SEL4LOGE("ERROR: invalid msg type: %d (%d)\n", hdr->msg_type, tty->recv_msg);
        ret = -EFAULT;
        goto err_out;
    }

    return ret;

err_out:
    if (hdr) {
        SEL4LOGI("tty recv hdr: type: %d, status: %d, len: %d\n", hdr->msg_type, hdr->status, hdr->length);
    }

    free(tty->recv_buf);
    tty->recv_buf = NULL;

    return ret;
}