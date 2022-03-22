/**
 * @file lwm2m_transport.c
 * @brief Network transport layer for LwM2M
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/******************************************************************************/
/* Includes                                                                   */
/******************************************************************************/
#include <zephyr/types.h>
#include <errno.h>

#include "lwm2m_transport.h"

/******************************************************************************/
/* Local Constant, Macro and Type Definitions                                 */
/******************************************************************************/
typedef struct lwm2m_transport_t {
	const char *name;
	struct lwm2m_transport_procedure *functions;
} LWM2M_TRANSPORT_T;

/******************************************************************************/
/* Local Data Definitions                                                     */
/******************************************************************************/
/** @brief Array of registered transports */
static LWM2M_TRANSPORT_T transports[CONFIG_LCZ_LWM2M_TRANSPORT_NUM];

/******************************************************************************/
/* Global Function Definitions                                                */
/******************************************************************************/
int lwm2m_transport_init(void)
{
	/* Reset the lists of transports */
	memset(transports, 0, sizeof(transports));
	return 0;
}

int lwm2m_transport_register(const char *name, struct lwm2m_transport_procedure *funcs)
{
	int err = 0;
	int i;

	/* Make sure that we aren't registering a duplicate */
	for (i = 0; i < CONFIG_LCZ_LWM2M_TRANSPORT_NUM; i++) {
		if (transports[i].name != NULL && strcmp(transports[i].name, name) == 0) {
			err = -EEXIST;
			break;
		}
	}

	/* If this isn't a duplicate, find a slot for it */
	if (err == 0) {
		err = -ENOMEM;
		for (i = 0; i < CONFIG_LCZ_LWM2M_TRANSPORT_NUM; i++) {
			if (transports[i].name == NULL) {
				transports[i].name = name;
				transports[i].functions = funcs;
				err = 0;
				break;
			}
		}
	}

	return err;
}

int lwm2m_transport_lookup(struct lwm2m_ctx *client_ctx)
{
	int i;

	/* Convert the transport name into an index into our table */
	client_ctx->transport_idx = -1;
	if (client_ctx->transport_name != NULL) {
		for (i = 0; i < CONFIG_LCZ_LWM2M_TRANSPORT_NUM; i++) {
			if (strcmp(transports[i].name, client_ctx->transport_name) == 0) {
				client_ctx->transport_idx = i;
			}
		}
	}

	if (client_ctx->transport_idx < 0) {
		return -ENOENT;
	} else {
		return 0;
	}
}

int lwm2m_transport_start(struct lwm2m_ctx *client_ctx)
{
	int err = -EINVAL;

	/* Convert the transport name into an index into our table */
	err = lwm2m_transport_lookup(client_ctx);

	/* If we found the transport, call the start function */
	if (client_ctx->transport_idx >= 0 &&
	    client_ctx->transport_idx < CONFIG_LCZ_LWM2M_TRANSPORT_NUM &&
	    transports[client_ctx->transport_idx].functions != NULL &&
	    transports[client_ctx->transport_idx].functions->start != NULL) {
		err = transports[client_ctx->transport_idx].functions->start(client_ctx);
	}

	return err;
}

int lwm2m_transport_send(struct lwm2m_ctx *client_ctx, const uint8_t *data, uint32_t datalen)
{
	int err = -EINVAL;

	if (client_ctx->transport_idx >= 0 &&
	    client_ctx->transport_idx < CONFIG_LCZ_LWM2M_TRANSPORT_NUM &&
	    transports[client_ctx->transport_idx].functions != NULL &&
	    transports[client_ctx->transport_idx].functions->send != NULL) {
		err = transports[client_ctx->transport_idx].functions->send(client_ctx, data,
									    datalen);
	}

	return err;
}

int lwm2m_transport_recv(struct lwm2m_ctx *client_ctx)
{
	int err = -EINVAL;

	if (client_ctx->transport_idx >= 0 &&
	    client_ctx->transport_idx < CONFIG_LCZ_LWM2M_TRANSPORT_NUM &&
	    transports[client_ctx->transport_idx].functions != NULL &&
	    transports[client_ctx->transport_idx].functions->recv != NULL) {
		err = transports[client_ctx->transport_idx].functions->recv(client_ctx);
	}

	return err;
}

int lwm2m_transport_close(struct lwm2m_ctx *client_ctx)
{
	int err = -EINVAL;

	if (client_ctx->transport_idx >= 0 &&
	    client_ctx->transport_idx < CONFIG_LCZ_LWM2M_TRANSPORT_NUM &&
	    transports[client_ctx->transport_idx].functions != NULL &&
	    transports[client_ctx->transport_idx].functions->close != NULL) {
		err = transports[client_ctx->transport_idx].functions->close(client_ctx);
	}

	return err;
}

int lwm2m_transport_is_connected(struct lwm2m_ctx *client_ctx)
{
	int ret = 1;

	if (client_ctx->transport_idx >= 0 &&
	    client_ctx->transport_idx < CONFIG_LCZ_LWM2M_TRANSPORT_NUM &&
	    transports[client_ctx->transport_idx].functions != NULL &&
	    transports[client_ctx->transport_idx].functions->is_connected != NULL) {
		ret = transports[client_ctx->transport_idx].functions->is_connected(client_ctx);
	}

	return ret;
}

void lwm2m_transport_tx_pending(struct lwm2m_ctx *client_ctx, bool pending)
{
	if (client_ctx->transport_idx >= 0 &&
	    client_ctx->transport_idx < CONFIG_LCZ_LWM2M_TRANSPORT_NUM &&
	    transports[client_ctx->transport_idx].functions != NULL &&
	    transports[client_ctx->transport_idx].functions->tx_pending != NULL) {
		transports[client_ctx->transport_idx].functions->tx_pending(client_ctx, pending);
	}
}

char *lwm2m_transport_print_addr(struct lwm2m_ctx *client_ctx, const struct sockaddr *addr)
{
	char *ret = NULL;

	if (client_ctx->transport_idx >= 0 &&
	    client_ctx->transport_idx < CONFIG_LCZ_LWM2M_TRANSPORT_NUM &&
	    transports[client_ctx->transport_idx].functions != NULL &&
	    transports[client_ctx->transport_idx].functions->print_addr != NULL) {
		ret = transports[client_ctx->transport_idx].functions->print_addr(client_ctx, addr);
	}

	if (ret == NULL) {
		ret = "<unknown>";
	}

	return ret;
}
