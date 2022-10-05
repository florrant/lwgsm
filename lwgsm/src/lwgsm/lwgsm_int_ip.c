/**
 * \file            lwgsm_input.c
 * \brief           Wrapper for passing input data to stack
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
/*********************
 *      INCLUDES
 *********************/
#include "lwgsm/lwgsm_int.h"
#include "lwgsm/lwgsm_private.h"
#include "system/lwgsm_ll.h"

/*********************
 *      DEFINES
 *********************/

/**********************
 *      TYPEDEFS
 **********************/

/**********************
 *  STATIC PROTOTYPES
 **********************/
static void reset_connections(uint8_t forced);
static void lwgsmi_send_conn_error_cb(lwgsm_msg_t* msg, lwgsmr_t error);

/**********************
 *  STATIC VARIABLES
 **********************/

/**********************
 *      MACROS
 **********************/
/* Temporary macros, only available for inside lwgsmi_process_sub_cmd function */
/* Set new command, but first check for error on previous */
#define SET_NEW_CMD_CHECK_ERROR(new_cmd)                                                                               \
    do {                                                                                                               \
        if (!*(is_error)) {                                                                                            \
            n_cmd = (new_cmd);                                                                                         \
        }                                                                                                              \
    } while (0)

/* Set new command, ignore result of previous */
#define SET_NEW_CMD(new_cmd)                                                                                           \
    do {                                                                                                               \
        n_cmd = (new_cmd);                                                                                             \
    } while (0)


/**
 * \brief           Free connection send data memory
 * \param[in]       m: Send data message type
 */
#define CONN_SEND_DATA_FREE(m)                                                                                         \
    do {                                                                                                               \
        if ((m) != NULL && (m)->msg.conn_send.fau) {                                                                   \
            (m)->msg.conn_send.fau = 0;                                                                                \
            if ((m)->msg.conn_send.data != NULL) {                                                                     \
                LWGSM_DEBUGF(LWGSM_CFG_DBG_CONN | LWGSM_DBG_TYPE_TRACE, "[LWGSM CONN] Free write buffer fau: %p\r\n",  \
                             (void*)(m)->msg.conn_send.data);                                                          \
                lwgsm_mem_free_s((void**)&((m)->msg.conn_send.data));                                                  \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

/**
 * \brief           Send connection callback for "data send"
 * \param[in]       m: Command message
 * \param[in]       err: Error of type \ref lwgsmr_t
 */
#define CONN_SEND_DATA_SEND_EVT(m, err)                                                                                \
    do {                                                                                                               \
        CONN_SEND_DATA_FREE(m);                                                                                        \
        lwgsm.evt.type = LWGSM_EVT_CONN_SEND;                                                                          \
        lwgsm.evt.evt.conn_data_send.res = err;                                                                        \
        lwgsm.evt.evt.conn_data_send.conn = (m)->msg.conn_send.conn;                                                   \
        lwgsm.evt.evt.conn_data_send.sent = (m)->msg.conn_send.sent_all;                                               \
        lwgsmi_send_conn_cb((m)->msg.conn_send.conn, NULL);                                                            \
    } while (0)

/**********************
 *  GLOBAL VARIABLES
 **********************/

/**********************
 *   GLOBAL FUNCTIONS
 **********************/
/**
 * \brief           Process events in case of timeout on command or invalid message (if device is not present)
 *
 *                  Function is called from processing thread:
 *
 *                      - On command timeout error
 *                      - If command was sent to queue and before processed, device present status changed
 *
 * \param[in]       msg: Current message
 * \param[in]       err: Error message to send
 */
void
lwgsmi_process_events_for_timeout_or_error_ip(lwgsm_msg_t* msg, lwgsmr_t err) {
    switch (msg->cmd_def) {
        case LWGSM_CMD_CIPSTART: {
            /* Start connection error */
            lwgsmi_send_conn_error_cb(msg, err);
            break;
        }

        case LWGSM_CMD_CIPSEND: {
            /* Send data error event */
            CONN_SEND_DATA_SEND_EVT(msg, err);
            break;
        }
        default:
            break;
    }
}

/**
 * \brief           Reset everything after reset was detected
 * \param[in]       forced: Set to `1` if reset forced by user
 */
void
lwgsmi_reset_everything_ip(uint8_t forced) {
    LWGSM_UNUSED(forced);
    /* Manually close all connections in memory */
    reset_connections(forced);

    /* Check if IPD active */
    if (lwgsm.m.ipd.buff != NULL) {
        lwgsm_pbuf_free(lwgsm.m.ipd.buff);
        lwgsm.m.ipd.buff = NULL;
    }
}

/**
 * \brief           Process connection callback
 * \note            Before calling function, callback structure must be prepared
 * \param[in]       conn: Pointer to connection to use as callback
 * \param[in]       evt: Event callback function for connection
 * \return          Member of \ref lwgsmr_t enumeration
 */
lwgsmr_t
lwgsmi_send_conn_cb(lwgsm_conn_t* conn, lwgsm_evt_fn evt) {
    if (conn->status.f.in_closing && lwgsm.evt.type != LWGSM_EVT_CONN_CLOSE) { /* Do not continue if in closing mode */
        /* return lwgsmOK; */
    }

    if (evt != NULL) {                                   /* Try with user connection */
        return evt(&lwgsm.evt);                          /* Call temporary function */
    } else if (conn != NULL && conn->evt_func != NULL) { /* Connection custom callback? */
        return conn->evt_func(&lwgsm.evt);               /* Process callback function */
    } else if (conn == NULL) {
        return lwgsmOK;
    }

    /*
     * On normal API operation,
     * we should never enter to this part of code
     */

    /*
     * If connection doesn't have callback function
     * automatically close the connection?
     *
     * Since function call is non-blocking,
     * it will set active connection to closing mode
     * and further callback events should not be executed anymore
     */
    return lwgsm_conn_close(conn, 0);
}

/**
 * \brief           Process and send data from device buffer
 * \return          Member of \ref lwgsmr_t enumeration
 */
static lwgsmr_t
lwgsmi_tcpip_process_send_data(void) {
    lwgsm_conn_t* c = lwgsm.msg->msg.conn_send.conn;
    if (!lwgsm_conn_is_active(c) ||                  /* Is the connection already closed? */
        lwgsm.msg->msg.conn_send.val_id != c->val_id /* Did validation ID change after we set parameter? */
    ) {
        /* Send event to user about failed send event */
        CONN_SEND_DATA_SEND_EVT(lwgsm.msg, lwgsmCLOSED);
        return lwgsmERR;
    }
    lwgsm.msg->msg.conn_send.sent = LWGSM_MIN(lwgsm.msg->msg.conn_send.btw, LWGSM_CFG_CONN_MAX_DATA_LEN);

    AT_PORT_SEND_BEGIN_AT();
    AT_PORT_SEND_CONST_STR("+CIPSEND=");
    lwgsmi_send_number(LWGSM_U32(c->num), 0, 0);                        /* Send connection number */
    lwgsmi_send_number(LWGSM_U32(lwgsm.msg->msg.conn_send.sent), 0, 1); /* Send length number */

    /* On UDP connections, IP address and port may be selected */
    if (c->type == LWGSM_CONN_TYPE_UDP) {
        if (lwgsm.msg->msg.conn_send.remote_ip != NULL && lwgsm.msg->msg.conn_send.remote_port) {
            lwgsmi_send_ip_mac(lwgsm.msg->msg.conn_send.remote_ip, 1, 1, 1); /* Send IP address including quotes */
            lwgsmi_send_port(lwgsm.msg->msg.conn_send.remote_port, 0, 1);    /* Send length number */
        }
    }
    AT_PORT_SEND_END_AT();
    return lwgsmOK;
}

/**
 * \brief           Process data sent and send remaining
 * \param[in]       sent: Status whether data were sent or not,
 *                      info received from GSM with "SEND OK" or "SEND FAIL"
 * \return          `1` in case we should stop sending or `0` if we still have data to process
 */
static uint8_t
lwgsmi_tcpip_process_data_sent(uint8_t sent) {
    if (sent) { /* Data were successfully sent */
        lwgsm.msg->msg.conn_send.sent_all += lwgsm.msg->msg.conn_send.sent;
        lwgsm.msg->msg.conn_send.btw -= lwgsm.msg->msg.conn_send.sent;
        lwgsm.msg->msg.conn_send.ptr += lwgsm.msg->msg.conn_send.sent;
        if (lwgsm.msg->msg.conn_send.bw != NULL) {
            *lwgsm.msg->msg.conn_send.bw += lwgsm.msg->msg.conn_send.sent;
        }
        lwgsm.msg->msg.conn_send.tries = 0;
    } else {                              /* We were not successful */
        ++lwgsm.msg->msg.conn_send.tries; /* Increase number of tries */
        if (lwgsm.msg->msg.conn_send.tries
            == LWGSM_CFG_MAX_SEND_RETRIES) { /* In case we reached max number of retransmissions */
            return 1;                        /* Return 1 and indicate error */
        }
    }
    if (lwgsm.msg->msg.conn_send.btw > 0) {                /* Do we still have data to send? */
        if (lwgsmi_tcpip_process_send_data() != lwgsmOK) { /* Check if we can continue */
            return 1;                                      /* Finish at this point */
        }
        return 0; /* We still have data to send */
    }
    return 1; /* Everything was sent, we can stop execution */
}

/**
 * \brief           Process CIPSEND response
 * \param[in]       rcv: Received data
 * \param[in,out]   is_ok: Pointer to current ok status
 * \param[in,out]   is_error: Pointer to current error status
 */
void
lwgsmi_process_cipsend_response(lwgsm_recv_t* rcv, uint8_t* is_ok, uint16_t* is_error) {
    if (lwgsm.msg->msg.conn_send.wait_send_ok_err) {
        if (LWGSM_CHARISNUM(rcv->data[0]) && rcv->data[1] == ',') {
            uint8_t num = LWGSM_CHARTONUM(rcv->data[0]);
            if (!strncmp(&rcv->data[3], "SEND OK" CRLF, 7 + CRLF_LEN)) {
                lwgsm.msg->msg.conn_send.wait_send_ok_err = 0;
                *is_ok = lwgsmi_tcpip_process_data_sent(1); /* Process as data were sent */
                if (*is_ok && lwgsm.msg->msg.conn_send.conn->status.f.active) {
                    CONN_SEND_DATA_SEND_EVT(lwgsm.msg, lwgsmOK);
                }
            } else if (!strncmp(&rcv->data[3], "SEND FAIL" CRLF, 9 + CRLF_LEN)) {
                lwgsm.msg->msg.conn_send.wait_send_ok_err = 0;
                *is_error = lwgsmi_tcpip_process_data_sent(
                    0); /* Data were not sent due to SEND FAIL or command didn't even start */
                if (*is_error && lwgsm.msg->msg.conn_send.conn->status.f.active) {
                    CONN_SEND_DATA_SEND_EVT(lwgsm.msg, lwgsmERR);
                }
            }
            LWGSM_UNUSED(num);
        }
        /* Check for an error or if connection closed in the meantime */
    } else if (*is_error) {
        CONN_SEND_DATA_SEND_EVT(lwgsm.msg, lwgsmERR);
    }
}

/**
 * \brief           Send error event to application layer
 * \param[in]       msg: Message from user with connection start
 * \param[in]       error: Error type
 */
static void
lwgsmi_send_conn_error_cb(lwgsm_msg_t* msg, lwgsmr_t error) {
    lwgsm.evt.type = LWGSM_EVT_CONN_ERROR; /* Connection error */
    lwgsm.evt.evt.conn_error.host = lwgsm.msg->msg.conn_start.host;
    lwgsm.evt.evt.conn_error.port = lwgsm.msg->msg.conn_start.port;
    lwgsm.evt.evt.conn_error.type = lwgsm.msg->msg.conn_start.type;
    lwgsm.evt.evt.conn_error.arg = lwgsm.msg->msg.conn_start.arg;
    lwgsm.evt.evt.conn_error.err = error;

    /* Call callback specified by user on connection startup */
    lwgsm.msg->msg.conn_start.evt_func(&lwgsm.evt);
    LWGSM_UNUSED(msg);
}

/**
 * \brief           Checks if connection pointer has valid address
 * \param[in]       conn: Address to check if valid connection ptr
 * \return          1 on success, 0 otherwise
 */
uint8_t
lwgsmi_is_valid_conn_ptr(lwgsm_conn_p conn) {
    uint8_t i = 0;
    for (i = 0; i < LWGSM_ARRAYSIZE(lwgsm.m.conns); ++i) {
        if (conn == &lwgsm.m.conns[i]) {
            return 1;
        }
    }
    return 0;
}

/**
 * \brief           Connection close event detected, process with callback to user
 * \param[in]       conn_num: Connection number
 * \param[in]       forced: Set to `1` if close forced by command, `0` otherwise
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsmi_conn_closed_process(uint8_t conn_num, uint8_t forced) {
    lwgsm_conn_t* conn = &lwgsm.m.conns[conn_num];

    conn->status.f.active = 0;

    /* Check if write buffer is set */
    if (conn->buff.buff != NULL) {
        LWGSM_DEBUGF(LWGSM_CFG_DBG_CONN | LWGSM_DBG_TYPE_TRACE, "[LWGSM CONN] Free write buffer: %p\r\n",
                     conn->buff.buff);
        lwgsm_mem_free_s((void**)&conn->buff.buff);
    }

    /* Send event */
    lwgsm.evt.type = LWGSM_EVT_CONN_CLOSE;
    lwgsm.evt.evt.conn_active_close.conn = conn;
    lwgsm.evt.evt.conn_active_close.forced = forced;
    lwgsm.evt.evt.conn_active_close.res = lwgsmOK;
    lwgsm.evt.evt.conn_active_close.client = conn->status.f.client;
    lwgsmi_send_conn_cb(conn, NULL);

    return 1;
}

/**
 * \brief           Function to initialize every AT command
 * \note            Never call this function directly. Set as initialization function for command and use `msg->fn(msg)`
 * \param[in]       msg: Pointer to \ref lwgsm_msg_t with data
 * \return          Member of \ref lwgsmr_t enumeration
 */
lwgsmr_t
lwgsmi_initiate_cmd_ip(lwgsm_msg_t* msg) {

    switch (CMD_GET_CUR()) {     /* Check current message we want to send over AT */
        case LWGSM_CMD_CIPMUX: { /* Enable multiple connections */
            AT_PORT_SEND_BEGIN_AT();
            AT_PORT_SEND_CONST_STR("+CIPMUX=1");
            AT_PORT_SEND_END_AT();
            break;
        }
        case LWGSM_CMD_CIPHEAD: { /* Enable information on receive data about connection and length */
            AT_PORT_SEND_BEGIN_AT();
            AT_PORT_SEND_CONST_STR("+CIPHEAD=1");
            AT_PORT_SEND_END_AT();
            break;
        }
        case LWGSM_CMD_CIPSRIP: {
            AT_PORT_SEND_BEGIN_AT();
            AT_PORT_SEND_CONST_STR("+CIPSRIP=1");
            AT_PORT_SEND_END_AT();
            break;
        }
        case LWGSM_CMD_CIPSSL: { /* Set SSL configuration */
            AT_PORT_SEND_BEGIN_AT();
            AT_PORT_SEND_CONST_STR("+CIPSSL=");
            lwgsmi_send_number((msg->msg.conn_start.type == LWGSM_CONN_TYPE_SSL) ? 1 : 0, 0, 0);
            AT_PORT_SEND_END_AT();
            break;
        }
        case LWGSM_CMD_CIPSTART: { /* Start a new connection */
            lwgsm_conn_t* c = NULL;

            /* Do we have network connection? */
            /* Check if we are connected to network */

            msg->msg.conn_start.num = 0;                             /* Start with max value = invalidated */
            for (int16_t i = LWGSM_CFG_MAX_CONNS - 1; i >= 0; --i) { /* Find available connection */
                if (!lwgsm.m.conns[i].status.f.active) {
                    c = &lwgsm.m.conns[i];
                    c->num = LWGSM_U8(i);
                    msg->msg.conn_start.num = LWGSM_U8(i); /* Set connection number for message structure */
                    break;
                }
            }
            if (c == NULL) {
                lwgsmi_send_conn_error_cb(msg, lwgsmERRNOFREECONN);
                return lwgsmERRNOFREECONN; /* We don't have available connection */
            }

            if (msg->msg.conn_start.conn != NULL) { /* Is user interested about connection info? */
                *msg->msg.conn_start.conn = c;      /* Save connection for user */
            }

            AT_PORT_SEND_BEGIN_AT();
            AT_PORT_SEND_CONST_STR("+CIPSTART=");
            lwgsmi_send_number(LWGSM_U32(c->num), 0, 0);
            if (msg->msg.conn_start.type == LWGSM_CONN_TYPE_UDP) {
                lwgsmi_send_string("UDP", 0, 1, 1);
            } else {
                lwgsmi_send_string("TCP", 0, 1, 1);
            }
            lwgsmi_send_string(msg->msg.conn_start.host, 0, 1, 1);
            lwgsmi_send_port(msg->msg.conn_start.port, 0, 1);
            AT_PORT_SEND_END_AT();
            break;
        }
        case LWGSM_CMD_CIPCLOSE: { /* Close the connection */
            lwgsm_conn_p c = msg->msg.conn_close.conn;
            if (c != NULL &&
                /* Is connection already closed or command for this connection is not valid anymore? */
                (!lwgsm_conn_is_active(c) || c->val_id != msg->msg.conn_close.val_id)) {
                return lwgsmERR;
            }
            AT_PORT_SEND_BEGIN_AT();
            AT_PORT_SEND_CONST_STR("+CIPCLOSE=");
            lwgsmi_send_number(
                LWGSM_U32(msg->msg.conn_close.conn ? msg->msg.conn_close.conn->num : LWGSM_CFG_MAX_CONNS), 0, 0);
            AT_PORT_SEND_END_AT();
            break;
        }
        case LWGSM_CMD_CIPSEND: {                    /* Send data to connection */
            return lwgsmi_tcpip_process_send_data(); /* Process send data */
        }
        case LWGSM_CMD_CIPSTATUS: { /* Get status of device and all connections */
            AT_PORT_SEND_BEGIN_AT();
            AT_PORT_SEND_CONST_STR("+CIPSTATUS");
            AT_PORT_SEND_END_AT();
            break;
        }
        default:
            return lwgsmERR; /* Invalid command */
    }
    return lwgsmOK; /* Valid command */
}

/**
 * \brief           Process current command with known execution status and start another if necessary
 * \param[in]       msg: Pointer to current message
 * \param[in]       is_ok: pointer to status whether last command result was OK
 * \param[in]       is_error: Pointer to status whether last command result was ERROR
 * \return          \ref lwgsmCONT if you sent more data and we need to process more data, \ref lwgsmOK on success, or \ref lwgsmERR on error
 */
lwgsmr_t
lwgsmi_process_sub_cmd_ip(lwgsm_msg_t* msg, uint8_t* is_ok, uint16_t* is_error) {
    lwgsm_cmd_t n_cmd = LWGSM_CMD_IDLE;
    if (CMD_IS_DEF(LWGSM_CMD_CIPSTART)) {
        if (!msg->i && CMD_IS_CUR(LWGSM_CMD_CIPSTATUS)) { /* Was the current command status info? */
            if (*is_ok) {
                SET_NEW_CMD(LWGSM_CMD_CIPSSL); /* Set SSL */
            }
        } else if (msg->i == 1 && CMD_IS_CUR(LWGSM_CMD_CIPSSL)) {
            SET_NEW_CMD(LWGSM_CMD_CIPSTART); /* Now actually start connection */
        } else if (msg->i == 2 && CMD_IS_CUR(LWGSM_CMD_CIPSTART)) {
            SET_NEW_CMD(LWGSM_CMD_CIPSTATUS); /* Go to status mode */
            if (*is_error) {
                msg->msg.conn_start.conn_res = LWGSM_CONN_CONNECT_ERROR;
            }
        } else if (msg->i == 3 && CMD_IS_CUR(LWGSM_CMD_CIPSTATUS)) {
            /* After second CIP status, define what to do next */
            switch (msg->msg.conn_start.conn_res) {
                case LWGSM_CONN_CONNECT_OK: {                                     /* Successfully connected */
                    lwgsm_conn_t* conn = &lwgsm.m.conns[msg->msg.conn_start.num]; /* Get connection number */

                    lwgsm.evt.type = LWGSM_EVT_CONN_ACTIVE; /* Connection just active */
                    lwgsm.evt.evt.conn_active_close.client = 1;
                    lwgsm.evt.evt.conn_active_close.conn = conn;
                    lwgsm.evt.evt.conn_active_close.forced = 1;
                    lwgsmi_send_conn_cb(conn, NULL);
                    lwgsmi_conn_start_timeout(conn); /* Start connection timeout timer */
                    break;
                }
                case LWGSM_CONN_CONNECT_ERROR: { /* Connection error */
                    lwgsmi_send_conn_error_cb(msg, lwgsmERRCONNFAIL);
                    *is_error = 1; /* Manually set error */
                    *is_ok = 0;    /* Reset success */
                    break;
                }
                default: {
                    /* Do nothing as of now */
                    break;
                }
            }
        }
    } else if (CMD_IS_DEF(LWGSM_CMD_CIPCLOSE)) {
        /*
         * It is unclear in which state connection is when ERROR is received on close command.
         * Stack checks if connection is closed before it allows and sends close command,
         * however it was detected that no automatic close event has been received from device
         * and AT+CIPCLOSE returned ERROR.
         *
         * Is it device firmware bug?
         */
        if (CMD_IS_CUR(LWGSM_CMD_CIPCLOSE) && *is_error) {
            /* Notify upper layer about failed close event */
            lwgsm.evt.type = LWGSM_EVT_CONN_CLOSE;
            lwgsm.evt.evt.conn_active_close.conn = msg->msg.conn_close.conn;
            lwgsm.evt.evt.conn_active_close.forced = 1;
            lwgsm.evt.evt.conn_active_close.res = lwgsmERR;
            lwgsm.evt.evt.conn_active_close.client =
                msg->msg.conn_close.conn->status.f.active && msg->msg.conn_close.conn->status.f.client;
            lwgsmi_send_conn_cb(msg->msg.conn_close.conn, NULL);
        }
    } else {
        return lwgsmCONT;
    }
    return lwgsmOK;
}

/**********************
 *   STATIC FUNCTIONS
 **********************/
#if LWGSM_CFG_CONN || __DOXYGEN__

/**
 * \brief           Reset all connections
 * \note            Used to notify upper layer stack to close everything and reset the memory if necessary
 * \param[in]       forced: Flag indicating reset was forced by user
 */
static void
reset_connections(uint8_t forced) {
    lwgsm.evt.type = LWGSM_EVT_CONN_CLOSE;
    lwgsm.evt.evt.conn_active_close.forced = forced;
    lwgsm.evt.evt.conn_active_close.res = lwgsmOK;

    for (size_t i = 0; i < LWGSM_CFG_MAX_CONNS; ++i) { /* Check all connections */
        if (lwgsm.m.conns[i].status.f.active) {
            lwgsm.m.conns[i].status.f.active = 0;

            lwgsm.evt.evt.conn_active_close.conn = &lwgsm.m.conns[i];
            lwgsm.evt.evt.conn_active_close.client = lwgsm.m.conns[i].status.f.client;
            lwgsmi_send_conn_cb(&lwgsm.m.conns[i], NULL); /* Send callback function */
        }
    }
}

#endif /* LWGSM_CFG_CONN || __DOXYGEN__ */

/**********************
 *   ERROR ASSERT
**********************/
