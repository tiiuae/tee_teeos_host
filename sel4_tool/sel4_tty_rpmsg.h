/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SEL4_TTY_RPMSG_H_
#define _SEL4_TTY_RPMSG_H_

#include <stdint.h>
#include <stdio.h>

#define HDR_LEN             sizeof(struct ree_tee_hdr)

#define SKIP_LEN_CHECK      0

#define SKIP_TEE_OK_CHECK   0
#define VERIFY_TEE_OK       1

struct tty_send_buf {
    char *buf;
    size_t buf_len;
};

#define TTY_SEND_BUF_COUNT  2
struct tty_msg {
    struct tty_send_buf send[TTY_SEND_BUF_COUNT];

    char *recv_buf;
    uint32_t recv_len;      /* expected response length (SKIP_LEN_CHECK) */
    int32_t recv_msg;       /* expected response msg (skip check: REE_TEE_INVALID) */
    uint8_t status_check;   /* VERIFY_TEE_OK: accept only TEE_OK status
                             * SKIP_TEE_OK_CHECK: hdr status not verified
                             */
};

int sel4_open_tty(void);
void sel4_close_tty(int fd);
int tty_req(int tty_fd, struct tty_msg *tty);

#endif /* _SEL4_TTY_RPMSG_H_ */