/**
 * @file lwm2m_transport.h
 * @brief Network transport layer for LwM2M
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __LWM2M_TRANSPORT_H__
#define __LWM2M_TRANSPORT_H__

/******************************************************************************/
/* Includes                                                                   */
/******************************************************************************/
#include <lcz_lwm2m.h>

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/
/* Global Function Prototypes                                                 */
/******************************************************************************/

/** @brief Initialize the transport layer
 *
 * @returns 0 on success or negative error code on error
 */
int lwm2m_transport_init(void);

/** @brief Ensure transport settings are correct
 *
 * This function is also called from within lwm2m_transport_start(). This
 * function is only needed when the transport is needed, but
 * lwm2m_transport_start() cannot be called.
 *
 * @param[in] client Identifies the client on which the procedure is requested.
 *
 * @returns 0 on success or negative error code on error
 */
int lwm2m_transport_lookup(struct lwm2m_ctx *client_ctx);

/** @brief Start the configured transport
 *
 * The function expects that client_ctx->name is set to the name of one of the
 * registered transports. If this is not true, the function will return an
 * error and the transport will not be started.
 *
 * @param[in] client Identifies the client on which the procedure is requested.
 *
 * @retval 0 or an error code indicating reason for failure.
 */
int lwm2m_transport_start(struct lwm2m_ctx *client_ctx);

/** @brief Handles write requests on configured transport.
 *
 * @param[in] client Identifies the client on which the procedure is requested.
 * @param[in] data Data to be written on the transport.
 * @param[in] datalen Length of data to be written on the transport.
 *
 * @retval 0 or an error code indicating reason for failure.
 */
int lwm2m_transport_send(struct lwm2m_ctx *client_ctx, const uint8_t *data, uint32_t datalen);

/** @brief Handles read requests on configured transport.
 *
 * @param[in] client Identifies the client on which the procedure is requested.
 *
 * @retval 0 or an error code indicating reason for failure.
 */
int lwm2m_transport_recv(struct lwm2m_ctx *client_ctx);

/** @brief Handles transport disconnection requests on configured transport.
 *
 * @param[in] client Identifies the client on which the procedure is requested.
 *
 * @retval 0 or an error code indicating reason for failure.
 */
int lwm2m_transport_close(struct lwm2m_ctx *client_ctx);

/** @brief Hook for client before poll() is called
 *
 * @param[in] client Identifies the client on which the procedure is requested.
 *
 * @retval 0 or an error code indicating reason for failure.
 */
int lwm2m_transport_is_connected(struct lwm2m_ctx *client_ctx);

/** @brief Hook for engine to inform the transport when data is ready to be transported
 *
 * @param[in] client Identifies the client on which the data is ready
 * @param[in] pending true if data needs to be sent, false if not
 */
void lwm2m_transport_tx_pending(struct lwm2m_ctx *client_ctx, bool pending);

/** @brief Transport-specific addres printer
 *
 * @param[in] client Identifies the client/transport address corresponds with
 * @param[in] addr Address to print
 *
 * @returns a pointer to a statically-allocated string representing the address
 */
char *lwm2m_transport_print_addr(struct lwm2m_ctx *client_ctx, const struct sockaddr *addr);

#if defined(CONFIG_LCZ_LWM2M_TRANSPORT_UDP)
/** @brief Register the UDP transport with the LwM2M engine
 *
 * @returns 0 on success or a negative error code
 */
int lwm2m_transport_udp_register(void);
#endif /* CONFIG_LWM2M_UDP_TRANSPORT */

#ifdef __cplusplus
}
#endif

#endif /* __LWM2M_TRANSPORT_H__ */
