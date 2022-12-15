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
#define is_ok    (*p_is_ok)
#define is_error (*p_is_error)

/**********************
 *      TYPEDEFS
 **********************/

/**********************
 *  STATIC PROTOTYPES
 **********************/
static void reset_connections(uint8_t forced);
static void lwgsmi_send_conn_error_cb(lwgsm_msg_t* msg, lwgsmr_t error);
//static void lwgsmi_process_cipsend_response(lwgsm_recv_t* rcv, uint8_t* p_is_ok, uint16_t* p_is_error);

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
        if (!*(p_is_error)) {                                                                                          \
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

// /**
//  * \brief           Parse connection info line from CIPSTATUS command
//  * \param[in]       str: Input string
//  * \param[in]       is_conn_line: Set to `1` for connection, `0` for general status
//  * \param[out]      continueScan: Pointer to output variable holding continue processing state
//  * \return          `1` on success, `0` otherwise
//  */
// uint8_t
// lwgsmi_parse_cipstatus_conn(const char* str, uint8_t is_conn_line, uint8_t* continueScan) {
//     uint8_t num;
//     lwgsm_conn_t* conn;
//     char s_tmp[16];
//     uint8_t tmp_pdp_state;

//     *continueScan = 1;
//     if (is_conn_line && (*str == 'C' || *str == 'S')) {
//         str += 3;
//     } else {
//         /* Check if PDP context is deactivated or not */
//         tmp_pdp_state = 1;
//         if (!strncmp(&str[7], "IP INITIAL", 10)) {
//             *continueScan = 0; /* Stop command execution at this point (no OK,ERROR received after this line) */
//             tmp_pdp_state = 0;
//         } else if (!strncmp(&str[7], "PDP DEACT", 9)) {
//             /* Deactivated */
//             tmp_pdp_state = 0;
//         }

//         /* Check if we have to update status for application */
//         if (lwgsm.m.network.is_attached != tmp_pdp_state) {
//             lwgsm.m.network.is_attached = tmp_pdp_state;

//             /* Notify upper layer */
//             lwgsmi_send_cb(lwgsm.m.network.is_attached ? LWGSM_EVT_NETWORK_ATTACHED : LWGSM_EVT_NETWORK_DETACHED);
//         }

//         return 1;
//     }

//     /* Parse connection line */
//     num = LWGSM_U8(lwgsmi_parse_number(&str));
//     conn = &lwgsm.m.conns[num];

//     conn->status.f.bearer = LWGSM_U8(lwgsmi_parse_number(&str));
//     lwgsmi_parse_string(&str, s_tmp, sizeof(s_tmp), 1); /* Parse TCP/UPD */
//     if (strlen(s_tmp)) {
//         if (!strcmp(s_tmp, "TCP")) {
//             conn->type = LWGSM_CONN_TYPE_TCP;
//         } else if (!strcmp(s_tmp, "UDP")) {
//             conn->type = LWGSM_CONN_TYPE_UDP;
//         }
//     }
//     lwgsmi_parse_ip(&str, &conn->remote_ip);
//     conn->remote_port = lwgsmi_parse_number(&str);

//     /* Get connection status */
//     lwgsmi_parse_string(&str, s_tmp, sizeof(s_tmp), 1);

//     /* TODO: Implement all connection states */
//     if (!strcmp(s_tmp, "INITIAL")) {

//     } else if (!strcmp(s_tmp, "CONNECTING")) {

//     } else if (!strcmp(s_tmp, "CONNECTED")) {

//     } else if (!strcmp(s_tmp, "REMOTE CLOSING")) {

//     } else if (!strcmp(s_tmp, "CLOSING")) {

//     } else if (!strcmp(s_tmp, "CLOSED")) {            /* Connection closed */
//         if (conn->status.f.active) {                  /* Check if connection is not */
//             lwgsmi_conn_closed_process(conn->num, 0); /* Process closed event */
//         }
//     }

//     /* Save last parsed connection */
//     lwgsm.m.active_conns_cur_parse_num = num;

//     return 1;
// }

// /**
//  * \brief           Parse IPD or RECEIVE statements
//  * \param[in]       str: Input string
//  * \return          `1` on success, `0` otherwise
//  */
// uint8_t
// lwgsmi_parse_ipd(const char* str) {
//     uint8_t conn;
//     size_t len;
//     lwgsm_conn_p c;

//     if (*str == '+') {
//         ++str;
//         if (*str == 'R') {
//             str += 8; /* Advance for RECEIVE */
//         } else {
//             str += 4; /* Advance for IPD */
//         }
//     }

//     conn = lwgsmi_parse_number(&str); /* Parse number for connection number */
//     len = lwgsmi_parse_number(&str);  /* Parse number for number of bytes to read */

//     c = conn < LWGSM_CFG_MAX_CONNS ? &lwgsm.m.conns[conn] : NULL; /* Get connection handle */
//     if (c == NULL) {                                              /* Invalid connection number */
//         return 0;
//     }

//     lwgsm.m.ipd.read = 1;      /* Start reading network data */
//     lwgsm.m.ipd.tot_len = len; /* Total number of bytes in this received packet */
//     lwgsm.m.ipd.rem_len = len; /* Number of remaining bytes to read */
//     lwgsm.m.ipd.conn = c;      /* Pointer to connection we have data for */

//     return 1;
// }

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
        case LWGSM_CMD_CAOPEN: {
            /* Start connection error */
            lwgsmi_send_conn_error_cb(msg, err);
            break;
        }

        case LWGSM_CMD_CASEND: {
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
    AT_PORT_SEND_CONST_STR("+CASEND=");
    lwgsmi_send_number(LWGSM_U32(c->num), 0, 0);                        /* Send connection number */
    lwgsmi_send_number(LWGSM_U32(lwgsm.msg->msg.conn_send.sent), 0, 1); /* Send length number */

    /* On UDP connections, IP address and port may be selected */ //FIXME: Seem not be the case when reading the documentation.
    // if (c->type == LWGSM_CONN_TYPE_UDP) {
    //     if (lwgsm.msg->msg.conn_send.remote_ip != NULL && lwgsm.msg->msg.conn_send.remote_port) {
    //         lwgsmi_send_ip_mac(lwgsm.msg->msg.conn_send.remote_ip, 1, 1, 1); /* Send IP address including quotes */
    //         lwgsmi_send_port(lwgsm.msg->msg.conn_send.remote_port, 0, 1);    /* Send length number */
    //     }
    // }
    AT_PORT_SEND_END_AT();

    //Send DATA
    lwgsm.msg->msg.conn_send.wait_send_ready = 1;
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

// /**
//  * \brief           Process CIPSEND response
//  * \param[in]       rcv: Received data
//  * \param[in,out]   is_ok: Pointer to current ok status
//  * \param[in,out]   is_error: Pointer to current error status
//  */
// static void
// lwgsmi_process_cipsend_response(lwgsm_recv_t* rcv, uint8_t* p_is_ok, uint16_t* p_is_error) {
//     if (lwgsm.msg->msg.conn_send.wait_send_ok_err) {
//         if (LWGSM_CHARISNUM(rcv->data[0]) && rcv->data[1] == ',') {
//             uint8_t num = LWGSM_CHARTONUM(rcv->data[0]);
//             if (!strncmp(&rcv->data[3], "SEND OK" CRLF, 7 + CRLF_LEN)) {
//                 lwgsm.msg->msg.conn_send.wait_send_ok_err = 0;
//                 is_ok = lwgsmi_tcpip_process_data_sent(1); /* Process as data were sent */
//                 if (is_ok && lwgsm.msg->msg.conn_send.conn->status.f.active) {
//                     CONN_SEND_DATA_SEND_EVT(lwgsm.msg, lwgsmOK);
//                 }
//             } else if (!strncmp(&rcv->data[3], "SEND FAIL" CRLF, 9 + CRLF_LEN)) {
//                 lwgsm.msg->msg.conn_send.wait_send_ok_err = 0;
//                 is_error = lwgsmi_tcpip_process_data_sent(
//                     0); /* Data were not sent due to SEND FAIL or command didn't even start */
//                 if (is_error && lwgsm.msg->msg.conn_send.conn->status.f.active) {
//                     CONN_SEND_DATA_SEND_EVT(lwgsm.msg, lwgsmERR);
//                 }
//             }
//             LWGSM_UNUSED(num);
//         }
//         /* Check for an error or if connection closed in the meantime */
//     } else if (is_error) {
//         CONN_SEND_DATA_SEND_EVT(lwgsm.msg, lwgsmERR);
//     }
// }

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

    switch (CMD_GET_CUR()) { /* Check current message we want to send over AT */
        // case LWGSM_CMD_CIPMUX: { /* Enable multiple connections */
        //     AT_PORT_SEND_BEGIN_AT();
        //     AT_PORT_SEND_CONST_STR("+CIPMUX=1");
        //     AT_PORT_SEND_END_AT();
        //     break;
        // }
        // case LWGSM_CMD_CIPHEAD: { /* Enable information on receive data about connection and length */
        //     AT_PORT_SEND_BEGIN_AT();
        //     AT_PORT_SEND_CONST_STR("+CIPHEAD=1");
        //     AT_PORT_SEND_END_AT();
        //     break;
        // }
        // case LWGSM_CMD_CIPSRIP: {
        //     AT_PORT_SEND_BEGIN_AT();
        //     AT_PORT_SEND_CONST_STR("+CIPSRIP=1");
        //     AT_PORT_SEND_END_AT();
        //     break;
        // }
        case LWGSM_CMD_CASSLCFG: { /* Set SSL configuration or not */
            //FIXME: Condition : (msg->msg.conn_start.type == LWGSM_CONN_TYPE_SSL)
            AT_PORT_SEND_BEGIN_AT();
            AT_PORT_SEND_CONST_STR("+CASSLCFG=");
            lwgsmi_send_number(0, 0, 0); // FIXME : need this LWGSM_U32(c->num)
            lwgsmi_send_string("SSL", 0, 1, 1);
            lwgsmi_send_number(0, 0, 1);
            AT_PORT_SEND_END_AT();
            break;
        }
        case LWGSM_CMD_CAOPEN: { /* Start a new connection */
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
            AT_PORT_SEND_CONST_STR("+CAOPEN=");
            lwgsmi_send_number(LWGSM_U32(c->num), 0, 0);
            lwgsmi_send_number(0, 0, 1);
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
        case LWGSM_CMD_CACLOSE: { /* Close the connection */
            lwgsm_conn_p c = msg->msg.conn_close.conn;
            if (c != NULL &&
                /* Is connection already closed or command for this connection is not valid anymore? */
                (!lwgsm_conn_is_active(c) || c->val_id != msg->msg.conn_close.val_id)) {
                return lwgsmERR;
            }
            AT_PORT_SEND_BEGIN_AT();
            AT_PORT_SEND_CONST_STR("+CACLOSE=");
            lwgsmi_send_number(
                LWGSM_U32(msg->msg.conn_close.conn ? msg->msg.conn_close.conn->num : LWGSM_CFG_MAX_CONNS), 0, 0);
            AT_PORT_SEND_END_AT();
            break;
        }
        case LWGSM_CMD_CASEND: {                     /* Send data to connection */
            return lwgsmi_tcpip_process_send_data(); /* Process send data */
        }
        case LWGSM_CMD_CARECV: { /* Send data to connection */
            lwgsm_conn_p c = msg->msg.conn_recv.conn;
            if (c != NULL &&
                /* Is connection already closed or command for this connection is not valid anymore? */
                (!lwgsm_conn_is_active(c) || c->val_id != msg->msg.conn_recv.val_id)) {
                return lwgsmERR;
            }
            AT_PORT_SEND_BEGIN_AT();
            AT_PORT_SEND_CONST_STR("+CARECV=");
            lwgsmi_send_number(LWGSM_U32(msg->msg.conn_recv.conn ? msg->msg.conn_recv.conn->num : LWGSM_CFG_MAX_CONNS),
                               0, 0);
            lwgsmi_send_number(LWGSM_CFG_CONN_MAX_DATA_LEN, 0,
                               1); //FIXME: MAgic number need be correled to maximum paquet readable by system
            AT_PORT_SEND_END_AT();
            break;
        }
        // case LWGSM_CMD_CIPSTATUS: { /* Get status of device and all connections */
        //     AT_PORT_SEND_BEGIN_AT();
        //     AT_PORT_SEND_CONST_STR("+CIPSTATUS");
        //     AT_PORT_SEND_END_AT();
        //     break;
        // }
        // case LWGSM_CMD_CIPMUX_SET: {
        //     AT_PORT_SEND_BEGIN_AT();
        //     AT_PORT_SEND_CONST_STR("+CIPMUX=1");
        //     AT_PORT_SEND_END_AT();
        //     break;
        // }
        // case LWGSM_CMD_CIPRXGET_SET: {
        //     AT_PORT_SEND_BEGIN_AT();
        //     AT_PORT_SEND_CONST_STR("+CIPRXGET=0");
        //     AT_PORT_SEND_END_AT();
        //     break;
        // }
        // case LWGSM_CMD_CSTT_SET: {
        //     AT_PORT_SEND_BEGIN_AT();
        //     AT_PORT_SEND_CONST_STR("+CSTT=");
        //     lwgsmi_send_string(msg->msg.network_attach.apn, 1, 1, 0);
        //     lwgsmi_send_string(msg->msg.network_attach.user, 1, 1, 1);
        //     lwgsmi_send_string(msg->msg.network_attach.pass, 1, 1, 1);
        //     AT_PORT_SEND_END_AT();
        //     break;
        // }
        // case LWGSM_CMD_CIICR: {
        //     AT_PORT_SEND_BEGIN_AT();
        //     AT_PORT_SEND_CONST_STR("+CIICR");
        //     AT_PORT_SEND_END_AT();
        //     break;
        // }
        // case LWGSM_CMD_CIFSR: {
        //     AT_PORT_SEND_BEGIN_AT();
        //     AT_PORT_SEND_CONST_STR("+CIFSR");
        //     AT_PORT_SEND_END_AT();
        //     break;
        // }
        // case LWGSM_CMD_CIPSHUT: { /* Shut down network connection and put to reset state */
        //     AT_PORT_SEND_BEGIN_AT();
        //     AT_PORT_SEND_CONST_STR("+CIPSHUT");
        //     AT_PORT_SEND_END_AT();
        //     break;
        // }
        case LWGSM_CMD_NETWORK_ATTACH:
        case LWGSM_CMD_CNACT: {
            AT_PORT_SEND_BEGIN_AT();
            AT_PORT_SEND_CONST_STR("+CNACT=");
            lwgsmi_send_number(msg->msg.args.num1, 0, 0);
            lwgsmi_send_number(msg->msg.args.num2, 0, 1);
            AT_PORT_SEND_END_AT();
            break;
        }
        case LWGSM_CMD_CNCFG: {
            AT_PORT_SEND_BEGIN_AT();
            AT_PORT_SEND_CONST_STR("+CNCFG=");
            lwgsmi_send_number(0, 0, 0);
            lwgsmi_send_number(0, 0, 1);
            lwgsmi_send_number(0, 0, 1);
            lwgsmi_send_string(msg->msg.network_attach.apn, 1, 1, 1);
            lwgsmi_send_string(msg->msg.network_attach.user, 1, 1, 1);
            lwgsmi_send_string(msg->msg.network_attach.pass, 1, 1, 1);
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
lwgsmi_process_sub_cmd_ip(lwgsm_msg_t* msg, uint8_t* p_is_ok, uint16_t* p_is_error) {
    // lwgsm_cmd_t n_cmd = LWGSM_CMD_IDLE;
    // if (CMD_IS_DEF(LWGSM_CMD_CAOPEN)) {
    //     if (is_ok) {

    //     }
    // }
    if (CMD_IS_DEF(LWGSM_CMD_CACLOSE)) {
        lwgsmi_conn_closed_process(lwgsm.msg->msg.conn_send.conn->num, 1);
    }

    // if (CMD_IS_DEF(LWGSM_CMD_CIPSTART)) {
    //     if (!msg->i && CMD_IS_CUR(LWGSM_CMD_CIPSTATUS)) { /* Was the current command status info? */
    //         if (is_ok) {
    //             SET_NEW_CMD(LWGSM_CMD_CIPSSL); /* Set SSL */
    //         }
    //     } else if (msg->i == 1 && CMD_IS_CUR(LWGSM_CMD_CIPSSL)) {
    //         SET_NEW_CMD(LWGSM_CMD_CIPSTART); /* Now actually start connection */
    //     } else if (msg->i == 2 && CMD_IS_CUR(LWGSM_CMD_CIPSTART)) {
    //         SET_NEW_CMD(LWGSM_CMD_CIPSTATUS); /* Go to status mode */
    //         if (is_error) {
    //             msg->msg.conn_start.conn_res = LWGSM_CONN_CONNECT_ERROR;
    //         }
    //     } else if (msg->i == 3 && CMD_IS_CUR(LWGSM_CMD_CIPSTATUS)) {
    //         /* After second CIP status, define what to do next */
    //         switch (msg->msg.conn_start.conn_res) {
    //             case LWGSM_CONN_CONNECT_OK: {                                     /* Successfully connected */
    //                 lwgsm_conn_t* conn = &lwgsm.m.conns[msg->msg.conn_start.num]; /* Get connection number */

    //                 lwgsm.evt.type = LWGSM_EVT_CONN_ACTIVE; /* Connection just active */
    //                 lwgsm.evt.evt.conn_active_close.client = 1;
    //                 lwgsm.evt.evt.conn_active_close.conn = conn;
    //                 lwgsm.evt.evt.conn_active_close.forced = 1;
    //                 lwgsmi_send_conn_cb(conn, NULL);
    //                 lwgsmi_conn_start_timeout(conn); /* Start connection timeout timer */
    //                 break;
    //             }
    //             case LWGSM_CONN_CONNECT_ERROR: { /* Connection error */
    //                 lwgsmi_send_conn_error_cb(msg, lwgsmERRCONNFAIL);
    //                 is_error = 1; /* Manually set error */
    //                 is_ok = 0;    /* Reset success */
    //                 break;
    //             }
    //             default: {
    //                 /* Do nothing as of now */
    //                 break;
    //             }
    //         }
    //     }
    // } else if (CMD_IS_DEF(LWGSM_CMD_CACLOSE)) { //FIXME: Seem CACLOSE will not return error, only CME error
    //     /*
    //      * It is unclear in which state connection is when ERROR is received on close command.
    //      * Stack checks if connection is closed before it allows and sends close command,
    //      * however it was detected that no automatic close event has been received from device
    //      * and AT+CACLOSE returned ERROR.
    //      *
    //      * Is it device firmware bug?
    //      */
    //     if (CMD_IS_CUR(LWGSM_CMD_CACLOSE) && is_error) {
    //         /* Notify upper layer about failed close event */
    //         lwgsm.evt.type = LWGSM_EVT_CONN_CLOSE;
    //         lwgsm.evt.evt.conn_active_close.conn = msg->msg.conn_close.conn;
    //         lwgsm.evt.evt.conn_active_close.forced = 1;
    //         lwgsm.evt.evt.conn_active_close.res = lwgsmERR;
    //         lwgsm.evt.evt.conn_active_close.client =
    //             msg->msg.conn_close.conn->status.f.active && msg->msg.conn_close.conn->status.f.client;
    //         lwgsmi_send_conn_cb(msg->msg.conn_close.conn, NULL);
    //     }
    // } else {
    //     return lwgsmCONT;
    // }
    // return lwgsmOK;
    //
    return lwgsmCONT;
}

void
lwgsmi_parse_received_ip(lwgsm_recv_t* rcv, uint8_t* p_is_ok, uint16_t* p_is_error) {

    /* Scan received strings which start with '+' */
    if (rcv->data[0] == '+') {
        uint8_t err;
        if (!strncmp(rcv->data, "+CADATAIND", 10)) {
            uint8_t conn;
            size_t len;
            lwgsm_conn_p c;
            const char* p_str = &rcv->data[12];
            conn = lwgsmi_parse_number(&p_str);                           /* Parse number for connection number */
            c = conn < LWGSM_CFG_MAX_CONNS ? &lwgsm.m.conns[conn] : NULL; /* Get connection handle */
            if (c == NULL) {                                              /* Invalid connection number */
                return;
            }

            //Send Reveive command //XXX: Temporary Send command (need create a function)
            LWGSM_MSG_VAR_DEFINE(msg);
            LWGSM_MSG_VAR_ALLOC(msg, 0);
            LWGSM_MSG_VAR_SET_EVT(msg, NULL, NULL);
            LWGSM_MSG_VAR_REF(msg).msg.conn_recv.conn = c;
            LWGSM_MSG_VAR_REF(msg).msg.conn_recv.val_id = lwgsmi_conn_get_val_id(c);
            LWGSM_MSG_VAR_REF(msg).cmd_def = LWGSM_CMD_CARECV;
            lwgsmr_t err = lwgsmi_send_msg_to_producer_mbox(&LWGSM_MSG_VAR_REF(msg), lwgsmi_initiate_cmd, 60000);
            if (err) {
                //XXX: Do something on error
            }
            lwgsm.m.ipd.pre_read = 1; /* Start reading network data */
            lwgsm.m.active_conns_cur_parse_num = conn;
        } else if (!strncmp(rcv->data, "+CARECV", 7)) {
            uint8_t conn;
            size_t len;
            lwgsm_conn_p c;
            const char* p_str = &rcv->data[9];
            len = lwgsmi_parse_number(&p_str); /* Parse number for number of bytes to read */
            //
            conn = lwgsm.m.active_conns_cur_parse_num;
            c = conn < LWGSM_CFG_MAX_CONNS ? &lwgsm.m.conns[conn] : NULL; /* Get connection handle */
            if (c == NULL) {                                              /* Invalid connection number */
                return;
            }

            lwgsm.m.ipd.pre_read = 0;
            lwgsm.m.ipd.read = 1;      /* Start reading network data */
            lwgsm.m.ipd.tot_len = len; /* Total number of bytes in this received packet */
            lwgsm.m.ipd.rem_len = len; /* Number of remaining bytes to read */
            lwgsm.m.ipd.conn = c;      /* Pointer to connection we have data for */

        } else if (!strncmp(rcv->data, "+CAOPEN", 7)) {
            uint8_t num = LWGSM_CHARTONUM(rcv->data[9]);
            if (num < LWGSM_CFG_MAX_CONNS) {
                uint8_t id;
                lwgsm_conn_t* conn = &lwgsm.m.conns[num]; /* Get connection handle */

                if (rcv->data[11] == '0') {
                    id = conn->val_id;
                    LWGSM_MEMSET(conn, 0x00, sizeof(*conn)); /* Reset connection parameters */
                    conn->num = num;
                    conn->status.f.active = 1;
                    conn->val_id = ++id; /* Set new validation ID */

                    /* Set connection parameters */
                    conn->status.f.client = 1;
                    conn->evt_func = lwgsm.msg->msg.conn_start.evt_func;
                    conn->arg = lwgsm.msg->msg.conn_start.arg;

                    /* Set type*/
                    conn->type = lwgsm.msg->msg.conn_start.type;
                    conn->remote_port = lwgsm.msg->msg.conn_start.port;
                    //conn->remote_ip;  //Get a way to retrieve ip from host

                    /* Set status */
                    lwgsm.msg->msg.conn_start.conn_res = LWGSM_CONN_CONNECT_OK;
                    is_ok = 1;
                } else {
                    lwgsm.msg->msg.conn_start.conn_res = LWGSM_CONN_CONNECT_ERROR;
                    is_error = 1;
                }
            }
            ////////////////////////////////////
            switch (lwgsm.msg->msg.conn_start.conn_res) {
                case LWGSM_CONN_CONNECT_OK: {                                           /* Successfully connected */
                    lwgsm_conn_t* conn = &lwgsm.m.conns[lwgsm.msg->msg.conn_start.num]; /* Get connection number */

                    lwgsm.evt.type = LWGSM_EVT_CONN_ACTIVE; /* Connection just active */
                    lwgsm.evt.evt.conn_active_close.client = 1;
                    lwgsm.evt.evt.conn_active_close.conn = conn;
                    lwgsm.evt.evt.conn_active_close.forced = 1;
                    lwgsmi_send_conn_cb(conn, NULL);
                    lwgsmi_conn_start_timeout(conn); /* Start connection timeout timer */
                    break;
                }
                case LWGSM_CONN_CONNECT_ERROR: { /* Connection error */
                    lwgsmi_send_conn_error_cb(lwgsm.msg, lwgsmERRCONNFAIL);
                    is_error = 1; /* Manually set error */
                    is_ok = 0;    /* Reset success */
                    break;
                }
                default: {
                    /* Do nothing as of now */
                    break;
                }
            }
        }
        //return (err == 1) ? lwgsmOK : lwgsmERR;
        /* Messages not starting with '+' sign */
    } else {
        if (rcv->len == 2 && rcv->data[0] == '>' && rcv->data[1] == ' ') {
            if ((CMD_IS_CUR(LWGSM_CMD_CASEND)) && (1 == lwgsm.msg->msg.conn_send.wait_send_ready)){
                lwgsm.msg->msg.conn_send.wait_send_ready = 0;
                AT_PORT_SEND_WITH_FLUSH(&lwgsm.msg->msg.conn_send.data[lwgsm.msg->msg.conn_send.ptr],
                                    lwgsm.msg->msg.conn_send.sent);
            }
            return;
        }
        // if (LWGSM_CHARISNUM(rcv->data[0]) && rcv->data[1] == ',' && rcv->data[2] == ' '
        //     && (!strncmp(&rcv->data[3], "CLOSE OK" CRLF, 8 + CRLF_LEN)
        //         || !strncmp(&rcv->data[3], "CLOSED" CRLF, 6 + CRLF_LEN))) {
        //     uint8_t forced = 0, num;

        //     num = LWGSM_CHARTONUM(rcv->data[0]); /* Get connection number */
        //     if (CMD_IS_CUR(LWGSM_CMD_CACLOSE) && lwgsm.msg->msg.conn_close.conn->num == num) {
        //         forced = 1;
        //         is_ok = 1; /* If forced and connection is closed, command is OK */
        //     }

        //     /* Manually stop send command? */
        //     if (CMD_IS_CUR(LWGSM_CMD_CIPSEND) && lwgsm.msg->msg.conn_send.conn->num == num) {
        //         /*
        //          * If active command is CIPSEND and CLOSED event received,
        //          * manually set error and process usual "ERROR" event on senddata
        //          */
        //         is_error = 1; /* This is an error in response */
        //         lwgsmi_process_cipsend_response(rcv, &is_ok, &is_error);
        //     }
        //     lwgsmi_conn_closed_process(num, forced); /* Connection closed, process */
        // } else if (CMD_IS_CUR(LWGSM_CMD_CIFSR) && LWGSM_CHARISNUM(rcv->data[0])) {
        //     const char* tmp = rcv->data;
        //     lwgsmi_parse_ip(&tmp, &lwgsm.m.network.ip_addr); /* Parse IP address */

        //     is_ok = 1; /* Manually set OK flag as we don't expect OK in CIFSR command */
        // }
    }

    /* Check general responses for active commands */
    if (lwgsm.msg != NULL) {
        // if (CMD_IS_CUR(LWGSM_CMD_CIPSTATUS)) {
        //     /* For CIPSTATUS, OK is returned before important data */
        //     if (is_ok) {
        //         is_ok = 0;
        //     }
        //     /* Check if connection data received */
        //     if (rcv->len > 3) {
        //         uint8_t continueScan = 0, processed = 0;
        //         if (rcv->data[0] == 'C' && rcv->data[1] == ':' && rcv->data[2] == ' ') {
        //             processed = 1;
        //             lwgsmi_parse_cipstatus_conn(rcv->data, 1, &continueScan);

        //             if (lwgsm.m.active_conns_cur_parse_num == (LWGSM_CFG_MAX_CONNS - 1)) {
        //                 is_ok = 1;
        //             }
        //         } else if (!strncmp(rcv->data, "STATE:", 6)) {
        //             processed = 1;
        //             lwgsmi_parse_cipstatus_conn(rcv->data, 0, &continueScan);
        //         }

        //         /* Check if we shall stop processing at this stage */
        //         if (processed && !continueScan) {
        //             is_ok = 1;
        //         }
        //     }
        // } else if (CMD_IS_CUR(LWGSM_CMD_CIPSEND)) {
        //     if (is_ok) {
        //         is_ok = 0;
        //     }
        //     lwgsmi_process_cipsend_response(rcv, &is_ok, &is_error);
        // }
    }
}

// /**
//  * \brief           Process input data received from GSM device
//  * \param[in]       data: Pointer to data to process
//  * \param[in]       data_len: Length of data to process in units of bytes
//  */
// void
// lwgsmi_process_ip(uint8_t ch, size_t d_len) {

//     if (lwgsm.m.ipd.read) { /* Read connection data */
//         size_t len;
//         size_t d; //FIXME: Not verified , it is wrong ???

//         if (lwgsm.m.ipd.buff != NULL) {                           /* Do we have active buffer? */
//             lwgsm.m.ipd.buff->payload[lwgsm.m.ipd.buff_ptr] = ch; /* Save data character */
//         }
//         ++lwgsm.m.ipd.buff_ptr;
//         --lwgsm.m.ipd.rem_len;

//         /* Try to read more data directly from buffer */
//         len = LWGSM_MIN(d_len, LWGSM_MIN(lwgsm.m.ipd.rem_len, lwgsm.m.ipd.buff != NULL
//                                                                   ? (lwgsm.m.ipd.buff->len - lwgsm.m.ipd.buff_ptr)
//                                                                   : lwgsm.m.ipd.rem_len));
//         LWGSM_DEBUGF(LWGSM_CFG_DBG_IPD | LWGSM_DBG_TYPE_TRACE, "[LWGSM IPD] New length to read: %d bytes\r\n",
//                      (int)len);
//         if (len > 0) {
//             if (lwgsm.m.ipd.buff != NULL) { /* Is buffer valid? */
//                 LWGSM_MEMCPY(&lwgsm.m.ipd.buff->payload[lwgsm.m.ipd.buff_ptr], d, len);
//                 LWGSM_DEBUGF(LWGSM_CFG_DBG_IPD | LWGSM_DBG_TYPE_TRACE, "[LWGSM IPD] Bytes read: %d\r\n", (int)len);
//             } else { /* Simply skip the data in buffer */
//                 LWGSM_DEBUGF(LWGSM_CFG_DBG_IPD | LWGSM_DBG_TYPE_TRACE, "[LWGSM IPD] Bytes skipped: %d\r\n", (int)len);
//             }
//             d_len -= len;                /* Decrease effective length */
//             d += len;                    /* Skip remaining length */
//             lwgsm.m.ipd.buff_ptr += len; /* Forward buffer pointer */
//             lwgsm.m.ipd.rem_len -= len;  /* Decrease remaining length */
//         }

//         /* Did we reach end of buffer or no more data? */
//         if (lwgsm.m.ipd.rem_len == 0 || (lwgsm.m.ipd.buff != NULL && lwgsm.m.ipd.buff_ptr == lwgsm.m.ipd.buff->len)) {
//             lwgsmr_t res = lwgsmOK;

//             /* Call user callback function with received data */
//             if (lwgsm.m.ipd.buff != NULL) {                                  /* Do we have valid buffer? */
//                 lwgsm.m.ipd.conn->total_recved += lwgsm.m.ipd.buff->tot_len; /* Increase number of bytes received */

//                 /*
//                      * Send data buffer to upper layer
//                      *
//                      * From this moment, user is responsible for packet
//                      * buffer and must free it manually
//                      */
//                 lwgsm.evt.type = LWGSM_EVT_CONN_RECV;
//                 lwgsm.evt.evt.conn_data_recv.buff = lwgsm.m.ipd.buff;
//                 lwgsm.evt.evt.conn_data_recv.conn = lwgsm.m.ipd.conn;
//                 res = lwgsmi_send_conn_cb(lwgsm.m.ipd.conn, NULL);

//                 lwgsm_pbuf_free(lwgsm.m.ipd.buff); /* Free packet buffer at this point */
//                 LWGSM_DEBUGF(LWGSM_CFG_DBG_IPD | LWGSM_DBG_TYPE_TRACE, "[LWGSM IPD] Free packet buffer\r\n");
//                 if (res == lwgsmOKIGNOREMORE) { /* We should ignore more data */
//                     LWGSM_DEBUGF(LWGSM_CFG_DBG_IPD | LWGSM_DBG_TYPE_TRACE,
//                                  "[LWGSM IPD] Ignoring more data from this IPD if available\r\n");
//                     lwgsm.m.ipd.buff = NULL; /* Set to NULL to ignore more data if possibly available */
//                 }

//                 /*
//                      * Create new data packet if case if:
//                      *
//                      *  - Previous one was successful and more data to read and
//                      *  - Connection is not in closing state
//                      */
//                 if (lwgsm.m.ipd.buff != NULL && lwgsm.m.ipd.rem_len > 0 && !lwgsm.m.ipd.conn->status.f.in_closing) {
//                     size_t new_len =
//                         LWGSM_MIN(lwgsm.m.ipd.rem_len, LWGSM_CFG_IPD_MAX_BUFF_SIZE); /* Calculate new buffer length */

//                     LWGSM_DEBUGF(LWGSM_CFG_DBG_IPD | LWGSM_DBG_TYPE_TRACE,
//                                  "[LWGSM IPD] Allocating new packet buffer of size: %d bytes\r\n", (int)new_len);
//                     lwgsm.m.ipd.buff = lwgsm_pbuf_new(new_len); /* Allocate new packet buffer */

//                     LWGSM_DEBUGW(LWGSM_CFG_DBG_IPD | LWGSM_DBG_TYPE_TRACE | LWGSM_DBG_LVL_WARNING,
//                                  lwgsm.m.ipd.buff == NULL, "[LWGSM IPD] Buffer allocation failed for %d bytes\r\n",
//                                  (int)new_len);
//                 } else {
//                     lwgsm.m.ipd.buff = NULL; /* Reset it */
//                 }
//             }
//             if (lwgsm.m.ipd.rem_len == 0) { /* Check if we read everything */
//                 lwgsm.m.ipd.buff = NULL;    /* Reset buffer pointer */
//                 lwgsm.m.ipd.read = 0;       /* Stop reading data */
//             }
//             lwgsm.m.ipd.buff_ptr = 0; /* Reset input buffer pointer */
//         }
//     }
//     //////////////////////////////////////////
// }

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
