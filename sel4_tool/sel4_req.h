/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SEL4_REQ_H_
#define _SEL4_REQ_H_

#include <stdint.h>
#include "ree_tee_msg.h"

struct serialized_param {
    uint32_t param_type;
    uint32_t val_len;
    uint8_t value[0];
};

int sel4_read_crashlog(char **crashlog, uint32_t *crashlog_len);
int sel4_open_comm(void);
void sel4_close_comm(int tee_fd);
int sel4_optee_open_session(int tee_fd, char **params_in_out, uint32_t *in_out_len, int32_t *tee_err, uint32_t *ta_err);
int sel4_optee_close_session(int tee_fd, char **params_in_out, uint32_t *in_out_len, int32_t *tee_err, uint32_t *ta_err);
int sel4_optee_invoke_cmd(int tee_fd, uint32_t ta_cmd, char **params_in_out, uint32_t *in_out_len, int32_t *tee_err, uint32_t *ta_err);
int sel4_req_debug_config(int tee_fd, uint64_t *debug_flags);
int sel4_optee_init(int tee_fd, uint8_t *storage, uint32_t storage_len);
int sel4_optee_export_storage(int tee_fd, uint8_t **storage, uint32_t *storage_len);

#endif /* _SEL4_REQ_H_ */