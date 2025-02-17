/**
 * \file            lwgsm_debug.h
 * \brief           Debugging inside GSM stack
 */

/*
 * Copyright (c) 2022 Tilen MAJERLE
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
 * AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * This file is part of LwGSM - Lightweight GSM-AT library.
 *
 * Author:          Tilen MAJERLE <tilen@majerle.eu>
 * Version:         v0.1.1
 */
#ifndef LWGSM_HDR_DEBUG_H
#define LWGSM_HDR_DEBUG_H

#include "lwgsm/lwgsm_opt.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * \ingroup         LWGSM
 * \defgroup        LWGSM_DEBUG Debugging support
 * \brief           Debugging support module to track stack
 * \{
 */

#if LWGSM_CFG_DBG && !defined(LWGSM_CFG_DBG_OUT)
#warning "LWGSM_CFG_DBG_OUT is not defined but debugging is enabled!"
#endif

#if (LWGSM_CFG_DBG && defined(LWGSM_CFG_DBG_OUT)) || __DOXYGEN__
/**
 * \brief           Print message to the debug "window" if enabled
 * \param[in]       c: Condition if debug of specific type is enabled
 * \param[in]       fmt: Formatted string for debug
 * \param[in]       ...: Variable parameters for formatted string
 */
#define LWGSM_DEBUGF(c, fmt, ...)                                                                                      \
    do {                                                                                                               \
        if (((c) & (LWGSM_DBG_ON)) && ((c) & (LWGSM_CFG_DBG_TYPES_ON))                                                 \
            && ((c)&LWGSM_DBG_LVL_MASK) >= (LWGSM_CFG_DBG_LVL_MIN)) {                                                  \
            LWGSM_CFG_DBG_OUT(fmt, ##__VA_ARGS__);                                                                     \
        }                                                                                                              \
    } while (0)

/**
 * \brief           Print message to the debug "window" if enabled when specific condition is met
 * \param[in]       c: Condition if debug of specific type is enabled
 * \param[in]       cond: Debug only if this condition is true
 * \param[in]       fmt: Formatted string for debug
 * \param[in]       ...: Variable parameters for formatted string
 */
#define LWGSM_DEBUGW(c, cond, fmt, ...)                                                                                \
    do {                                                                                                               \
        if (cond) {                                                                                                    \
            LWGSM_DEBUGF(c, fmt, ##__VA_ARGS__);                                                                       \
        }                                                                                                              \
    } while (0)
#else
#undef LWGSM_CFG_DBG
#define LWGSM_CFG_DBG LWGSM_DBG_OFF
#define LWGSM_DEBUGF(c, fmt, ...)
#define LWGSM_DEBUGW(c, cond, fmt, ...)
#endif /* (LWGSM_CFG_DBG && defined(LWGSM_CFG_DBG_OUT)) || __DOXYGEN__ */

/**
 * \}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LWGSM_HDR_DEBUG_H */
