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

int sel4_req_key_creation(uint32_t format, uint32_t nbits, uint32_t clientid, const char *name, struct key_data_blob **output, uint32_t *output_len);
int sel4_req_key_import(struct key_data_blob *input_blob, uint32_t blob_size);
int sel4_read_crashlog(char **crashlog, uint32_t *crashlog_len);
int sel4_optee_open_session(char **params_in_out, uint32_t *in_out_len, int32_t *tee_err, uint32_t *ta_err);
int sel4_optee_invoke_cmd(uint32_t ta_cmd, char **params_in_out, uint32_t *in_out_len, int32_t *tee_err, uint32_t *ta_err);
int sel4_req_debug_config(uint64_t *debug_flags);

#endif /* _SEL4_REQ_H_ */