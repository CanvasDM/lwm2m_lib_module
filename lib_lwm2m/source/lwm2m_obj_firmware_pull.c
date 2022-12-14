/*
 * Copyright (c) 2017 Linaro Limited
 * Copyright (c) 2018-2019 Foundries.io
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_MODULE_NAME net_lwm2m_obj_firmware_pull
#define LOG_LEVEL CONFIG_LCZ_LWM2M_LOG_LEVEL

#include <logging/log.h>
LOG_MODULE_REGISTER(LOG_MODULE_NAME);

#include <string.h>

#include "lwm2m_pull_context.h"
#include "lwm2m_engine.h"

static char *proxy_uri = NULL;
static load_credentials_cb_t load_credentials = NULL;

static void set_update_result(uint16_t obj_inst_id, int error_code)
{
	int result;

	if (!error_code) {
		lwm2m_firmware_set_update_state_inst(obj_inst_id, STATE_DOWNLOADED);
		return;
	}

	switch (error_code) {
	case -ENOMEM:
		result = RESULT_OUT_OF_MEM;
		break;
	case -ENOSPC:
		result = RESULT_NO_STORAGE;
		break;
	case -EFAULT:
		result = RESULT_INTEGRITY_FAILED;
		break;
	case -ENOMSG:
		result = RESULT_CONNECTION_LOST;
		break;
	case -ENOTSUP:
		result = RESULT_INVALID_URI;
		break;
	case -EPROTONOSUPPORT:
		result = RESULT_UNSUP_PROTO;
		break;
	default:
		result = RESULT_UPDATE_FAILED;
		break;
	}

	lwm2m_firmware_set_update_result(result);
}

static struct requesting_object req = {
	.obj_inst_id = 0,
	.is_firmware_uri = true,
	.result_cb = set_update_result,
	.verify_cb = NULL
};

/* TODO: */
int lwm2m_firmware_cancel_transfer(void)
{
	return 0;
}

int lwm2m_firmware_start_transfer(uint16_t obj_inst_id, char *package_uri)
{
	int error_code;

	req.write_cb = lwm2m_firmware_get_write_cb();
	req.proxy_uri = (const char *)proxy_uri;
	req.load_credentials = load_credentials;

	/* start file transfer work */
	error_code = lwm2m_pull_context_start_transfer(package_uri, req, K_NO_WAIT);

	if (error_code) {
		return error_code;
	}

	lwm2m_firmware_set_update_state_inst(obj_inst_id, STATE_DOWNLOADING);

	return 0;
}

void lwm2m_firmware_set_proxy_uri(char *uri)
{
	proxy_uri = uri;
}

const char *lwm2m_firmware_get_proxy_uri(void)
{
	return (const char *)proxy_uri;
}

void lwm2m_firmware_set_credential_cb(load_credentials_cb_t credential_cb)
{
	load_credentials = credential_cb;
}

load_credentials_cb_t lwm2m_firmware_get_credential_cb(void)
{
	return load_credentials;
}