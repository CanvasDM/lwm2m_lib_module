/*
 * Copyright (c) 2017 Linaro Limited
 * Copyright (c) 2018-2019 Foundries.io
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Uses some original concepts by:
 *         Joakim Eriksson <joakime@sics.se>
 *         Niclas Finne <nfi@sics.se>
 *         Joel Hoglund <joel@sics.se>
 */

#define LOG_MODULE_NAME net_lwm2m_udp
#define LOG_LEVEL CONFIG_LCZ_LWM2M_LOG_LEVEL

#include <logging/log.h>
LOG_MODULE_REGISTER(LOG_MODULE_NAME);

#include <fcntl.h>
#include <zephyr/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <init.h>
#include <sys/printk.h>
#include <net/net_ip.h>
#include <net/http_parser_url.h>
#include <net/socket.h>
#if defined(CONFIG_LCZ_LWM2M_DTLS_SUPPORT)
#include <net/tls_credentials.h>
#include <mbedtls/ssl.h>
#endif
#if defined(CONFIG_DNS_RESOLVER)
#include <net/dns_resolve.h>
#endif

#include "lwm2m_transport.h"
#include "lwm2m_object.h"
#include "lwm2m_engine.h"
#include "lwm2m_util.h"

/******************************************************************************
* Local function prototypes
******************************************************************************/

static int lwm2m_transport_udp_start(struct lwm2m_ctx *client_ctx);
static int lwm2m_transport_udp_send(struct lwm2m_ctx *client_ctx, const uint8_t *data,
				    uint32_t len);
static int lwm2m_transport_udp_recv(struct lwm2m_ctx *client_ctx);
static int lwm2m_transport_udp_close(struct lwm2m_ctx *client_ctx);
static int lwm2m_transport_udp_is_connected(struct lwm2m_ctx *client_ctx);
static void lwm2m_transport_udp_tx_pending(struct lwm2m_ctx *client_ctx, bool pending);
static char *lwm2m_transport_udp_print_addr(struct lwm2m_ctx *client_ctx,
					    const struct sockaddr *addr);

/******************************************************************************
* Local variables
******************************************************************************/

static struct lwm2m_transport_procedure udp_transport = {
	lwm2m_transport_udp_start,
	lwm2m_transport_udp_send,
	lwm2m_transport_udp_recv,
	lwm2m_transport_udp_close,
	lwm2m_transport_udp_is_connected,
	lwm2m_transport_udp_tx_pending,
	lwm2m_transport_udp_print_addr
};

/******************************************************************************
* Global functions
******************************************************************************/

int lwm2m_transport_udp_register(void)
{
	return lwm2m_transport_register("udp", &udp_transport);
}

/******************************************************************************
* Local functions
******************************************************************************/

static int lwm2m_transport_udp_send(struct lwm2m_ctx *client_ctx, const uint8_t *data,
				    uint32_t datalen)
{
	return send(client_ctx->sock_fd, data, datalen, 0);
}

static int lwm2m_transport_udp_close(struct lwm2m_ctx *client_ctx)
{
	int rc = 0;

	if (client_ctx != NULL && client_ctx->sock_fd >= 0) {
		rc = close(client_ctx->sock_fd);
		client_ctx->sock_fd = -1;
	}

	return rc;
}

static int lwm2m_transport_udp_recv(struct lwm2m_ctx *client_ctx)
{
	static uint8_t in_buf[NET_IPV6_MTU];
	socklen_t from_addr_len;
	ssize_t len;
	static struct sockaddr from_addr;

	from_addr_len = sizeof(from_addr);
	len = recvfrom(client_ctx->sock_fd, in_buf, sizeof(in_buf) - 1, 0, &from_addr,
		       &from_addr_len);

	if (len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return -errno;
		}

		LOG_ERR("Error reading response: %d", errno);
		if (client_ctx->fault_cb != NULL) {
			client_ctx->fault_cb(client_ctx, errno);
		}
		return -errno;
	}

	if (len == 0) {
		LOG_ERR("Zero length recv");
		return 0;
	}

	in_buf[len] = 0U;
	lwm2m_coap_receive(client_ctx, in_buf, len, &from_addr);

	return 0;
}

#if defined(CONFIG_LCZ_LWM2M_DTLS_SUPPORT)
static int load_tls_credential(struct lwm2m_ctx *client_ctx, uint16_t res_id,
			       enum tls_credential_type type)
{
	int ret = 0;
	void *cred = NULL;
	uint16_t cred_len;
	uint8_t cred_flags;
	char pathstr[MAX_RESOURCE_LEN];

	/* ignore error value */
	tls_credential_delete(client_ctx->tls_tag, type);

	snprintk(pathstr, sizeof(pathstr), "0/%d/%u", client_ctx->sec_obj_inst, res_id);

	ret = lwm2m_engine_get_res_data(pathstr, &cred, &cred_len, &cred_flags);
	if (ret < 0) {
		LOG_ERR("Unable to get resource data for '%s'", log_strdup(pathstr));
		return ret;
	}

	ret = tls_credential_add(client_ctx->tls_tag, type, cred, cred_len);
	if (ret < 0) {
		LOG_ERR("Error setting cred tag %d type %d: Error %d", client_ctx->tls_tag, type,
			ret);
	}

	return ret;
}
#endif /* CONFIG_LCZ_LWM2M_DTLS_SUPPORT */

int lwm2m_socket_start(struct lwm2m_ctx *client_ctx)
{
	int flags;
#if defined(CONFIG_LCZ_LWM2M_DTLS_SUPPORT)
	int ret;
	uint8_t tmp;

	if (client_ctx->load_credentials) {
		ret = client_ctx->load_credentials(client_ctx);
		if (ret < 0) {
			LOG_ERR("load_credentials failed: %d", ret);
			return ret;
		}
	} else {
		ret = load_tls_credential(client_ctx, 3, TLS_CREDENTIAL_PSK_ID);
		if (ret < 0) {
			LOG_ERR("load_tls_credential(PSK_ID) failed %d", ret);
			return ret;
		}

		ret = load_tls_credential(client_ctx, 5, TLS_CREDENTIAL_PSK);
		if (ret < 0) {
			LOG_ERR("load_tls_credential(PSK) failed %d", ret);
			return ret;
		}
	}

	if (client_ctx->use_dtls) {
		client_ctx->sock_fd =
			socket(client_ctx->remote_addr.sa_family, SOCK_DGRAM, IPPROTO_DTLS_1_2);
	} else
#endif /* CONFIG_LCZ_LWM2M_DTLS_SUPPORT */
	{
		client_ctx->sock_fd =
			socket(client_ctx->remote_addr.sa_family, SOCK_DGRAM, IPPROTO_UDP);
	}

	if (client_ctx->sock_fd < 0) {
		LOG_ERR("Failed to create socket: %d", errno);
		return -errno;
	}

#if defined(CONFIG_LCZ_LWM2M_DTLS_SUPPORT)
	if (client_ctx->use_dtls) {
		sec_tag_t tls_tag_list[] = {
			client_ctx->tls_tag,
		};

		ret = setsockopt(client_ctx->sock_fd, SOL_TLS, TLS_SEC_TAG_LIST, tls_tag_list,
				 sizeof(tls_tag_list));
		if (ret < 0) {
			LOG_ERR("Failed to set TLS_SEC_TAG_LIST option: %d", errno);
			lwm2m_engine_context_close(client_ctx);
			return -errno;
		}

		if (client_ctx->desthostname != NULL) {
			/** store character at len position */
			tmp = client_ctx->desthostname[client_ctx->desthostnamelen];

			/** change it to '\0' to pass to socket*/
			client_ctx->desthostname[client_ctx->desthostnamelen] = '\0';

			/** mbedtls ignores length */
			ret = setsockopt(client_ctx->sock_fd, SOL_TLS, TLS_HOSTNAME,
					 client_ctx->desthostname, client_ctx->desthostnamelen);

			/** restore character */
			client_ctx->desthostname[client_ctx->desthostnamelen] = tmp;
			if (ret < 0) {
				LOG_ERR("Failed to set TLS_HOSTNAME option: %d", errno);
				return -errno;
			}
		}
	}
#endif /* CONFIG_LCZ_LWM2M_DTLS_SUPPORT */

	if (connect(client_ctx->sock_fd, &client_ctx->remote_addr, NET_SOCKADDR_MAX_SIZE) < 0) {
		LOG_ERR("Cannot connect UDP (-%d)", errno);
		lwm2m_engine_context_close(client_ctx);
		return -errno;
	}

	flags = fcntl(client_ctx->sock_fd, F_GETFL, 0);
	if (flags == -1) {
		return -errno;
	}
	fcntl(client_ctx->sock_fd, F_SETFL, flags | O_NONBLOCK);

	return 0;
}

int lwm2m_parse_peerinfo(char *url, struct lwm2m_ctx *client_ctx, bool is_firmware_uri)
{
	struct http_parser_url parser;
#if defined(CONFIG_LCZ_LWM2M_DNS_SUPPORT)
	struct addrinfo *res, hints = { 0 };
#endif
	int ret;
	uint16_t off, len;
	uint8_t tmp;

	LOG_DBG("Parse url: %s", log_strdup(url));

	http_parser_url_init(&parser);
	ret = http_parser_parse_url(url, strlen(url), 0, &parser);
	if (ret < 0) {
		LOG_ERR("Invalid url: %s", log_strdup(url));
		return -ENOTSUP;
	}

	off = parser.field_data[UF_SCHEMA].off;
	len = parser.field_data[UF_SCHEMA].len;

	/* check for supported protocol */
	if (strncmp(url + off, "coaps", len) != 0) {
		return -EPROTONOSUPPORT;
	}

	/* check for DTLS requirement */
	client_ctx->use_dtls = false;
	if (len == 5U && strncmp(url + off, "coaps", len) == 0) {
#if defined(CONFIG_LCZ_LWM2M_DTLS_SUPPORT)
		client_ctx->use_dtls = true;
#else
		return -EPROTONOSUPPORT;
#endif /* CONFIG_LCZ_LWM2M_DTLS_SUPPORT */
	}

	if (!(parser.field_set & (1 << UF_PORT))) {
		if (is_firmware_uri && client_ctx->use_dtls) {
			/* Set to default coaps firmware update port */
			parser.port = CONFIG_LCZ_LWM2M_FIRMWARE_PORT_SECURE;
		} else if (is_firmware_uri) {
			/* Set to default coap firmware update port */
			parser.port = CONFIG_LCZ_LWM2M_FIRMWARE_PORT_NONSECURE;
		} else {
			/* Set to default LwM2M server port */
			parser.port = CONFIG_LCZ_LWM2M_PEER_PORT;
		}
	}

	off = parser.field_data[UF_HOST].off;
	len = parser.field_data[UF_HOST].len;

#if defined(CONFIG_LCZ_LWM2M_DTLS_SUPPORT)
	/** copy url pointer to be used in socket */
	client_ctx->desthostname = url + off;
	client_ctx->desthostnamelen = len;
#endif

	/* truncate host portion */
	tmp = url[off + len];
	url[off + len] = '\0';

	/* initialize remote_addr */
	(void)memset(&client_ctx->remote_addr, 0, sizeof(client_ctx->remote_addr));

	/* try and set IP address directly */
	client_ctx->remote_addr.sa_family = AF_INET6;
	ret = net_addr_pton(AF_INET6, url + off,
			    &((struct sockaddr_in6 *)&client_ctx->remote_addr)->sin6_addr);
	/* Try to parse again using AF_INET */
	if (ret < 0) {
		client_ctx->remote_addr.sa_family = AF_INET;
		ret = net_addr_pton(AF_INET, url + off,
				    &((struct sockaddr_in *)&client_ctx->remote_addr)->sin_addr);
	}

	if (ret < 0) {
#if defined(CONFIG_LCZ_LWM2M_DNS_SUPPORT)
#if defined(CONFIG_NET_IPV6) && defined(CONFIG_NET_IPV4)
		hints.ai_family = AF_UNSPEC;
#elif defined(CONFIG_NET_IPV6)
		hints.ai_family = AF_INET6;
#elif defined(CONFIG_NET_IPV4)
		hints.ai_family = AF_INET;
#else
		hints.ai_family = AF_UNSPEC;
#endif /* defined(CONFIG_NET_IPV6) && defined(CONFIG_NET_IPV4) */
		hints.ai_socktype = SOCK_DGRAM;
		ret = getaddrinfo(url + off, NULL, &hints, &res);
		if (ret != 0) {
			LOG_ERR("Unable to resolve address");
			/* DNS error codes don't align with normal errors */
			ret = -ENOENT;
			goto cleanup;
		}

		memcpy(&client_ctx->remote_addr, res->ai_addr, sizeof(client_ctx->remote_addr));
		client_ctx->remote_addr.sa_family = res->ai_family;
		freeaddrinfo(res);
#else
		goto cleanup;
#endif /* CONFIG_LCZ_LWM2M_DNS_SUPPORT */
	}

	/* set port */
	if (client_ctx->remote_addr.sa_family == AF_INET6) {
		net_sin6(&client_ctx->remote_addr)->sin6_port = htons(parser.port);
	} else if (client_ctx->remote_addr.sa_family == AF_INET) {
		net_sin(&client_ctx->remote_addr)->sin_port = htons(parser.port);
	} else {
		ret = -EPROTONOSUPPORT;
	}

cleanup:
	/* restore host separator */
	url[off + len] = tmp;
	return ret;
}

static int lwm2m_transport_udp_start(struct lwm2m_ctx *client_ctx)
{
	char pathstr[MAX_RESOURCE_LEN];
	char *url;
	uint16_t url_len;
	uint8_t url_data_flags;
	int ret = 0U;

	/* get the server URL */
	snprintk(pathstr, sizeof(pathstr), "0/%d/0", client_ctx->sec_obj_inst);
	ret = lwm2m_engine_get_res_data(pathstr, (void **)&url, &url_len, &url_data_flags);
	if (ret < 0) {
		return ret;
	}

	url[url_len] = '\0';
	ret = lwm2m_parse_peerinfo(url, client_ctx, false);
	if (ret < 0) {
		return ret;
	}

	return lwm2m_socket_start(client_ctx);
}

static int lwm2m_transport_udp_is_connected(struct lwm2m_ctx *client_ctx)
{
	/*
	 * UDP is connectionless, but this could be changed in the future to
	 * only return true when the underlying network interface is ready.
	 */
	return true;
}

static void lwm2m_transport_udp_tx_pending(struct lwm2m_ctx *client_ctx, bool pending)
{
	/* nothing to do */
}

static char *lwm2m_transport_udp_print_addr(struct lwm2m_ctx *client_ctx,
					    const struct sockaddr *addr)
{
	static char buf[NET_IPV6_ADDR_LEN];

	if (addr->sa_family == AF_INET6) {
		return net_addr_ntop(AF_INET6, &net_sin6(addr)->sin6_addr, buf, sizeof(buf));
	}

	if (addr->sa_family == AF_INET) {
		return net_addr_ntop(AF_INET, &net_sin(addr)->sin_addr, buf, sizeof(buf));
	}

	LOG_ERR("Unknown IP address family:%d", addr->sa_family);
	strcpy(buf, "unk");
	return buf;
}
