/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SEL4_REQ_H_
#define _SEL4_REQ_H_

#include <stdint.h>
#include "ree_tee_msg.h"

int sel4_req_key_creation(uint32_t format, uint32_t nbits, uint32_t clientid, const char *name, struct key_data_blob **output, uint32_t *output_len);
int sel4_req_key_import(struct key_data_blob *input_blob, uint32_t blob_size);
int sel4_read_crashlog(char **crashlog, uint32_t *crashlog_len);

#endif /* _SEL4_REQ_H_ */