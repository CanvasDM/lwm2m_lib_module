/*
 * Copyright (c) 2017 Linaro Limited
 * Copyright (c) 2018-2019 Foundries.io
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <lcz_lwm2m.h>
#include <sys_clock.h>

#define LWM2M_PACKAGE_URI_LEN CONFIG_LCZ_LWM2M_SWMGMT_PACKAGE_URI_LEN

struct requesting_object {
	uint8_t obj_inst_id;
	bool is_firmware_uri;
	const uint8_t *proxy_uri;

	load_credentials_cb_t load_credentials;
	void (*result_cb)(uint16_t obj_inst_id, int error_code);
	lwm2m_engine_set_data_cb_t write_cb;
	int (*verify_cb)(void);
};

/*
 * The pull context is also used in the LWM2M's Software Management object.
 * This means that the transfer needs to know if it's used for firmware or
 * something else.
 */
int lwm2m_pull_context_start_transfer(char *uri, struct requesting_object req, k_timeout_t timeout);
