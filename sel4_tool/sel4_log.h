/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SEL4_LOG_H_
#define _SEL4_LOG_H_

#ifdef SEL4LOG_INFO
#define SEL4LOGI(...)   printf(__VA_ARGS__)
#else
#define SEL4LOGI(...)
#endif

#ifdef SEL4LOG_ERROR
#define SEL4LOGE(...)   printf(__VA_ARGS__)
#else
#define SEL4LOGE(...)
#endif

#endif /* _SEL4_LOG_H_ */