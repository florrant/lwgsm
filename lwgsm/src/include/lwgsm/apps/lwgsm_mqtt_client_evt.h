/**
 * \file            lwgsm_mqtt_client_evt.h
 * \brief           MQTT client event helper functions
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
#ifndef LWGSM_HDR_APP_MQTT_CLIENT_EVT_H
#define LWGSM_HDR_APP_MQTT_CLIENT_EVT_H

#include "lwgsm/apps/lwgsm_mqtt_client.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * \ingroup         LWGSM_APP_MQTT_CLIENT
 * \defgroup        LWGSM_APP_MQTT_CLIENT_EVT Event helper functions
 * \brief           Event helper functions
 * \{
 */

/**
 * \brief           Get MQTT event type
 * \param[in]       client: MQTT client
 * \param[in]       evt: Event handle
 * \return          MQTT Event type, value of \ref lwgsm_mqtt_evt_type_t enumeration
 * \hideinitializer
 */
#define lwgsm_mqtt_client_evt_get_type(client, evt)           ((lwgsm_mqtt_evt_type_t)(evt)->type)

/**
 * \anchor          LWGSM_APP_MQTT_CLIENT_EVT_CONNECT
 * \name            Connect event
 * \{
 *
 * \note            Use these functions on \ref LWGSM_MQTT_EVT_CONNECT event
 */

/**
 * \brief           Get connection status
 * \param[in]       client: MQTT client
 * \param[in]       evt: Event handle
 * \return          Connection status. Member of \ref lwgsm_mqtt_conn_status_t
 * \hideinitializer
 */
#define lwgsm_mqtt_client_evt_connect_get_status(client, evt) ((lwgsm_mqtt_conn_status_t)(evt)->evt.connect.status)

/**
 * \}
 */

/**
 * \anchor          LWGSM_APP_MQTT_CLIENT_EVT_DISCONNECT
 * \name            Disconnect event
 * \{
 *
 * \note            Use these functions on \ref LWGSM_MQTT_EVT_DISCONNECT event
 */

/**
 * \brief           Check if MQTT client was accepted by server when disconnect event occurred
 * \param[in]       client: MQTT client
 * \param[in]       evt: Event handle
 * \return          `1` on success, `0` otherwise
 * \hideinitializer
 */
#define lwgsm_mqtt_client_evt_disconnect_is_accepted(client, evt)                                                      \
    ((lwgsm_mqtt_conn_status_t)(evt)->evt.disconnect.is_accepted)

/**
 * \}
 */

/**
 * \anchor          LWGSM_APP_MQTT_CLIENT_EVT_SUB_UNSUB
 * \name            Subscribe/unsubscribe event
 * \{
 *
 * \note            Use these functions on \ref LWGSM_MQTT_EVT_SUBSCRIBE or \ref LWGSM_MQTT_EVT_UNSUBSCRIBE events
 */

/**
 * \brief           Get user argument used on \ref lwgsm_mqtt_client_subscribe
 * \param[in]       client: MQTT client
 * \param[in]       evt: Event handle
 * \return          User argument
 * \hideinitializer
 */
#define lwgsm_mqtt_client_evt_subscribe_get_argument(client, evt)       ((void*)(evt)->evt.sub_unsub_scribed.arg)

/**
 * \brief           Get result of subscribe event
 * \param[in]       client: MQTT client
 * \param[in]       evt: Event handle
 * \return          \ref lwgsmOK on success, member of \ref lwgsmr_t otherwise
 * \hideinitializer
 */
#define lwgsm_mqtt_client_evt_subscribe_get_result(client, evt)         ((lwgsmr_t)(evt)->evt.sub_unsub_scribed.res)

/**
 * \brief           Get user argument used on \ref lwgsm_mqtt_client_unsubscribe
 * \param[in]       client: MQTT client
 * \param[in]       evt: Event handle
 * \return          User argument
 * \hideinitializer
 */
#define lwgsm_mqtt_client_evt_unsubscribe_get_argument(client, evt)     ((void*)(evt)->evt.sub_unsub_scribed.arg)

/**
 * \brief           Get result of unsubscribe event
 * \param[in]       client: MQTT client
 * \param[in]       evt: Event handle
 * \return          \ref lwgsmOK on success, member of \ref lwgsmr_t otherwise
 * \hideinitializer
 */
#define lwgsm_mqtt_client_evt_unsubscribe_get_result(client, evt)       ((lwgsmr_t)(evt)->evt.sub_unsub_scribed.res)

/**
 * \}
 */

/**
 * \anchor          LWGSM_APP_MQTT_CLIENT_EVT_PUBLISH_RECV
 * \name            Publish receive event
 * \{
 *
 * \note            Use these functions on \ref LWGSM_MQTT_EVT_PUBLISH_RECV event
 */

/**
 * \brief           Get topic from received publish packet
 * \param[in]       client: MQTT client
 * \param[in]       evt: Event handle
 * \return          Topic name
 * \hideinitializer
 */
#define lwgsm_mqtt_client_evt_publish_recv_get_topic(client, evt)       ((const void*)(evt)->evt.publish_recv.topic)

/**
 * \brief           Get topic length from received publish packet
 * \param[in]       client: MQTT client
 * \param[in]       evt: Event handle
 * \return          Topic length
 * \hideinitializer
 */
#define lwgsm_mqtt_client_evt_publish_recv_get_topic_len(client, evt)   (LWGSM_SZ((evt)->evt.publish_recv.topic_len))

/**
 * \brief           Get payload from received publish packet
 * \param[in]       client: MQTT client
 * \param[in]       evt: Event handle
 * \return          Packet payload
 * \hideinitializer
 */
#define lwgsm_mqtt_client_evt_publish_recv_get_payload(client, evt)     ((const void*)(evt)->evt.publish_recv.payload)

/**
 * \brief           Get payload length from received publish packet
 * \param[in]       client: MQTT client
 * \param[in]       evt: Event handle
 * \return          Payload length
 * \hideinitializer
 */
#define lwgsm_mqtt_client_evt_publish_recv_get_payload_len(client, evt) (LWGSM_SZ((evt)->evt.publish_recv.payload_len))

/**
 * \brief           Check if packet is duplicated
 * \param[in]       client: MQTT client
 * \param[in]       evt: Event handle
 * \return          `1` if duplicated, `0` otherwise
 * \hideinitializer
 */
#define lwgsm_mqtt_client_evt_publish_recv_is_duplicate(client, evt)    (LWGSM_U8((evt)->evt.publish_recv.dup))

/**
 * \brief           Get received quality of service
 * \param[in]       client: MQTT client
 * \param[in]       evt: Event handle
 * \return          Member of \ref lwgsm_mqtt_qos_t enumeration
 * \hideinitializer
 */
#define lwgsm_mqtt_client_evt_publish_recv_get_qos(client, evt)         ((evt)->evt.publish_recv.qos)

/**
 * \}
 */

/**
 * \anchor          LWGSM_APP_MQTT_CLIENT_EVT_PUBLISH
 * \name            Publish event
 * \{
 *
 * \note            Use these functions on \ref LWGSM_MQTT_EVT_PUBLISH event
 */

/**
 * \brief           Get user argument used on \ref lwgsm_mqtt_client_publish
 * \param[in]       client: MQTT client
 * \param[in]       evt: Event handle
 * \return          User argument
 * \hideinitializer
 */
#define lwgsm_mqtt_client_evt_publish_get_argument(client, evt)         ((void*)(evt)->evt.publish.arg)

/**
* \brief           Get result of publish event
* \param[in]       client: MQTT client
* \param[in]       evt: Event handle
* \return          \ref lwgsmOK on success, member of \ref lwgsmr_t otherwise
* \hideinitializer
*/
#define lwgsm_mqtt_client_evt_publish_get_result(client, evt)           ((lwgsmr_t)(evt)->evt.publish.res)

/**
 * \}
 */

/**
 * \}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LWGSM_HDR_APP_MQTT_CLIENT_EVT_H */
