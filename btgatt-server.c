/*
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Google Inc.
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <locale.h>
#include <signal.h>
#include <pwd.h>
#include <getopt.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include <time.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <errno.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <assert.h>


#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/hci_lib.h"
#include "lib/l2cap.h"
#include "lib/uuid.h"

#include "src/shared/mainloop.h"
#include "src/shared/util.h"
#include "src/shared/att.h"
#include "src/shared/queue.h"
#include "src/shared/timeout.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-server.h"

//#include <glib-2.0/glib.h>
//#include <NetworkManager/NetworkManager.h>
//#include <libnm-glib/libnm_glib.h>
//#include <libnm-glib/nm-client.h>
#include "btgatt-server.h"
#include "udpclient.h"

#define UUID_GAP			0x1800
#define UUID_GATT			0x1801
#define UUID_HEART_RATE			0x180d
#define UUID_HEART_RATE_MSRMT		0x2a37
#define UUID_HEART_RATE_BODY		0x2a38
#define UUID_HEART_RATE_CTRL		0x2a39

#define ATT_CID 4

#define PRLOG(...) \
	do { \
		printf(__VA_ARGS__); \
		print_prompt(); \
	} while (0)

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#define COLOR_OFF	"\x1B[0m"
#define COLOR_RED	"\x1B[0;91m"
#define COLOR_GREEN	"\x1B[0;92m"
#define COLOR_YELLOW	"\x1B[0;93m"
#define COLOR_BLUE	"\x1B[0;94m"
#define COLOR_MAGENTA	"\x1B[0;95m"
#define COLOR_BOLDGRAY	"\x1B[1;30m"
#define COLOR_BOLDWHITE	"\x1B[1;37m"

static const char test_device_name[] = "Yezhik_1234";

static const char test_wifi_name[] = "WIFI_TEST_NAME";

static const char test_wifi_password[] = "12345678";

static bool verbose = false;

static bool is_wifi_on = false;

static int piloting_udp_socket = -1;

struct server {
	int fd;
	struct bt_att *att;
	struct gatt_db *db;
	struct bt_gatt_server *gatt;

	uint8_t *device_name;
	size_t name_len;
	
	uint8_t *wifi_name;
	size_t wifi_len;

	uint8_t *wifi_password;
	size_t wifi_password_len;

	uint8_t *wifi_error;
	size_t wifi_error_len;

	uint8_t *wifi_list;
	size_t wifi_list_len;

	uint16_t gatt_svc_chngd_handle;
	bool svc_chngd_enabled;

	uint16_t hr_handle;
	uint16_t hr_msrmt_handle;
	uint16_t hr_energy_expended;
	uint16_t wifi_turned_off;
	bool hr_visible;
	bool hr_msrmt_enabled;
	int hr_ee_count;
	unsigned int hr_timeout_id;
};

static void print_prompt(void)
{
	printf(COLOR_BLUE "[GATT server]" COLOR_OFF "# ");
	fflush(stdout);
}

static void att_disconnect_cb(int err, void *user_data)
{
	printf("Device disconnected: %s\n", strerror(err));

	mainloop_quit();
}


static void conf_cb(void *user_data)
{
	PRLOG("Received confirmation\n");
}

static void att_debug_cb(const char *str, void *user_data)
{
	const char *prefix = user_data;

	PRLOG(COLOR_BOLDGRAY "%s" COLOR_BOLDWHITE "%s\n" COLOR_OFF, prefix,
									str);
}

static void gatt_debug_cb(const char *str, void *user_data)
{
	const char *prefix = user_data;

	PRLOG(COLOR_GREEN "%s%s\n" COLOR_OFF, prefix, str);
}

static void gap_device_name_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t error = 0;
	size_t len = 0;
	const uint8_t *value = NULL;

	PRLOG("GAP Device Name Read called\n");

	len = server->name_len;

	if (offset > len) {
		error = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	len -= offset;
	value = len ? &server->device_name[offset] : NULL;

done:
	gatt_db_attribute_read_result(attrib, id, error, value, len);
}

static void gap_device_wifi_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t error = 0;
	size_t len = 0;
	const uint8_t *value = NULL;

	PRLOG("GAP WiFi Name Read called\n");

	len = server->wifi_len;

	if (offset > len) {
		error = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	len -= offset;
	value = len ? &server->wifi_name[offset] : NULL;

done:
	gatt_db_attribute_read_result(attrib, id, error, value, len);
}

static void gap_device_wifi_password_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t error = 0;
	size_t len = 0;
	const uint8_t *value = NULL;

	PRLOG("GAP WiFi Password Read called\n");

	len = server->wifi_password_len;

	if (offset > len) {
		error = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	len -= offset;
	value = len ? &server->wifi_password[offset] : NULL;

done:
	gatt_db_attribute_read_result(attrib, id, error, value, len);
}

static void gap_device_piloting_message_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t error = 0;
	size_t len = 0;
	const uint8_t *value = NULL;

	PRLOG("GAP Piloting message read called\n");

done:
	gatt_db_attribute_read_result(attrib, id, error, value, len);
}

static void gap_device_name_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t error = 0;

	PRLOG("GAP Device Name Write called\n");

	/* If the value is being completely truncated, clean up and return */
	if (!(offset + len)) {
		free(server->device_name);
		server->device_name = NULL;
		server->name_len = 0;
		goto done;
	}

	/* Implement this as a variable length attribute value. */
	if (offset > server->name_len) {
		error = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (offset + len != server->name_len) {
		uint8_t *name;

		name = realloc(server->device_name, offset + len);
		if (!name) {
			error = BT_ATT_ERROR_INSUFFICIENT_RESOURCES;
			goto done;
		}

		server->device_name = name;
		server->name_len = offset + len;
	}

	if (value)
		memcpy(server->device_name + offset, value, len);

done:
	gatt_db_attribute_write_result(attrib, id, error);
}

static void gap_device_wifi_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t error = 0;

	PRLOG("GAP WiFi Name Write called\n");

	PRLOG("%s %d %d", value, offset, len);


	/* If the value is being completely truncated, clean up and return */
	if (!(offset + len)) {
		free(server->wifi_name);
		server->wifi_name = NULL;
		server->wifi_len = 0;
		goto done;
	}

	/* Implement this as a variable length attribute value. */
	if (offset > server->wifi_len) {
		error = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (offset + len != server->wifi_len) {
		uint8_t *name;

		name = realloc(server->wifi_name, offset + len);
		if (!name) {
			error = BT_ATT_ERROR_INSUFFICIENT_RESOURCES;
			goto done;
		}

		server->wifi_name = name;
		server->wifi_len = offset + len;
	}

	if (value)
	{
		strncpy(server->wifi_name, value, len);
		server->wifi_len = len;
	}

	PRLOG("name %s", server->wifi_name);

done:
	gatt_db_attribute_write_result(attrib, id, error);
}

static void gap_device_wifi_password_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t error = 0;

	PRLOG("GAP WiFi Password Write called\n");

	PRLOG("%s %d %d", value, offset, len);

	/* If the value is being completely truncated, clean up and return */
	if (!(offset + len)) {
		free(server->wifi_password);
		server->wifi_password = NULL;
		server->wifi_password_len = 0;
		goto done;
	}

	/* Implement this as a variable length attribute value. */
	if (offset > server->wifi_password_len) {
		error = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (offset + len != server->wifi_password_len) {
		uint8_t *name;

		name = realloc(server->wifi_password, offset + len);
		if (!name) {
			error = BT_ATT_ERROR_INSUFFICIENT_RESOURCES;
			goto done;
		}

		server->wifi_password = name;
		server->wifi_password_len = offset + len;
	}

	if (value)
	{
		strncpy(server->wifi_password, value, len);
		server->wifi_password_len = len;
	}

	char connect_to_wifi[100] = "sudo nmcli d wifi connect ";
	char* SSID = server->wifi_name; //"\"";
	//strncat(SSID, server->wifi_name, server->wifi_len);
	//strncat(SSID, "\"", 2);
	const char* password_word = " password ";
	char* PASS = server->wifi_password;

  	strncat(connect_to_wifi, SSID, server->wifi_len);
	strncat(connect_to_wifi, password_word, 10);
	strncat(connect_to_wifi, PASS, server->wifi_password_len);
	strncat(connect_to_wifi, " 2> ./bt_logs.txt ", 19);

	PRLOG("%s", connect_to_wifi);
	system("sudo nmcli device wifi list > /dev/null 2>&1");
	system("umask 0; touch ./bt_logs.txt");
	system(connect_to_wifi);

	int c;
	FILE *file;
	file = fopen("./bt_logs.txt", "r");

	char error_buf[1024];
	memset(error_buf, 0, 1024);

	int i = 0;
	
	if (file) 
	{
		printf("logs from bt_logs: ");
		while ((c = getc(file)) != EOF)
		{
			error_buf[i++] = c;
		}
		printf("%s", error_buf);
		fclose(file);
		//system("rm bt_logs.txt");

		if(!bt_gatt_server_send_notification(server->gatt,
							server->wifi_turned_off,
							error_buf,
							1024))
		{
			printf("shit\n");
		}

		if(!bt_gatt_server_send_notification(server->gatt,
							0x2941,
							error_buf,
							1024))
		{
			printf("shit2\n");
		}

		if(!bt_gatt_server_send_notification(server->gatt,
					0x2902,
					error_buf,
					1024))
		{
			printf("shit3\n");
		}

		if(!bt_gatt_server_send_notification(server->gatt,
			0x28ff,
			error_buf,
			1024))
		{
			printf("shit3\n");
		}

		if(!bt_gatt_server_send_indication(server->gatt, 0x2A05,
							error_buf, 1024,
							conf_cb, NULL, NULL))
		printf("Failed to initiate indication\n");
	}



	///////////

	len = i;
	offset = 0;

	if (!(offset + len)) {
		free(server->wifi_error);
		server->wifi_error = NULL;
		server->wifi_error_len = 0;
		goto done;
	}

	/* Implement this as a variable length attribute value. */
	if (offset > server->wifi_error_len) {
		error = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (offset + len != server->wifi_error_len) {
		uint8_t *name;

		name = realloc(server->wifi_error, offset + len);
		if (!name) {
			error = BT_ATT_ERROR_INSUFFICIENT_RESOURCES;
			goto done;
		}

		server->wifi_error = name;
		server->wifi_error_len = offset + len;
	}

	if (error_buf)
	{
		strncpy(server->wifi_error, error_buf, len);
		server->wifi_error_len = len;
	}

	//get error and notify

done:
	PRLOG("done");
	gatt_db_attribute_write_result(attrib, id, error);
}



static void gap_device_wifi_list_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t error = 0;
	size_t len = 0;
	const uint8_t *value = NULL;

	PRLOG("GAP WiFi List Read called\n");

	len = server->wifi_list_len;

	if (offset > len) {
		error = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	len -= offset;
	value = len ? &server->wifi_list[offset] : NULL;



done:
	gatt_db_attribute_read_result(attrib, id, error, value, len);
}

static void gap_device_wifi_list_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t error = 0;

	PRLOG("GAP WiFi List Write called\n");

		//////////////////////////////////////////////////////////

	system("umask 0; touch ./wifi_list.txt");
	system("nmcli device wifi rescan");
	sleep(10);
	system("sudo nmcli --get-values ssid,signal device wifi list > ./wifi_list.txt ");

	int c;
	FILE *file;
	file = fopen("./wifi_list.txt", "r");

	char wifi_buf[2048];
	memset(wifi_buf, 0, 2048);

	int i = 0;
	char json[2048] = "{";

	int cnt = 0;
	int json_cnt = 1;
	
	if (file) 
	{
		printf("logs from wifi_list: ");
		while ((c = getc(file)) != EOF)
		{
			cnt++;
			if(c == ':')
			{
				char ssid[100];
				strncpy(ssid, wifi_buf, i);
				ssid[i+1] = '\0';

				strncat(json, "\"", 2);
				json_cnt += 2;
				strncat(json, ssid, i);
				json_cnt += i;
				strncat(json, "\"", 2);
				json_cnt += 2;
				strncat(json, ":", 1);
				json_cnt += 1;

				i = 0;
			}
			else if(c == '\n')
			{
				int result = 0;
				int strSignal = 0;

				char level[3];
				strncpy(level, wifi_buf, i);
				level[i] = '\0';

				strSignal = atoi(level);

				//printf("strSignal = %d, level = %s\n", strSignal, level);

				if (strSignal >= 80)
					result = 5;          //-30 - Maximum signal strength, you are probably standing right next to the access point.  
				else if (strSignal >= 60)  //-50    #Anything down to this level can be considered excellent signal strength.    
					result = 4;          //-60     #Good, reliable signal strength.     
				else if (strSignal >= 40)
					result = 3;          //-67     #Reliable signal strength.   The minimum for any service depending on a reliable connection and signal strength, such as voice over Wi-Fi and non-HD video streaming.
				else if (strSignal >= 25)
					result = 2;
				else if (strSignal >= 10)
					result = 1;          //-70     #Not a strong signal.    Light browsing and email.
										//-80     #Unreliable signal strength, will not suffice for most services.     Connecting to the network.
										//-90     #The chances of even connecting are very low at this level.
				i = 0;

				char res[3];
				sprintf(res, "%d", result);

				strncat(json, res, 1);
				json_cnt += 1;
				strncat(json, ",", 1);		
				json_cnt += 1;
			}
			else
			{
				wifi_buf[i++] = c;
			}
		}

		json[strlen(json) - 1] = '}';
		printf("json = %s\n", json);
		fclose(file);
		//system("rm ./wifi_list.txt");
	}

	len = strlen(json);
	value = json;
	offset = 0;

	if (offset + len != server->wifi_list_len) {
		uint8_t *name;

		name = realloc(server->wifi_list, offset + len);
		if (!name) {
			error = BT_ATT_ERROR_INSUFFICIENT_RESOURCES;
			goto done;
		}

		server->wifi_list = name;
		server->wifi_list_len = offset + len;
	}

	if (value)
	{
		strncpy(server->wifi_list, value, len);
		server->wifi_list_len = len;
	}

	//PRLOG("%s %d %d", value, offset, len);

done:
	PRLOG("done");
	gatt_db_attribute_write_result(attrib, id, error);
}

static void gap_device_piloting_message_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t error = 0;

	PRLOG("GAP piloting_message Write called\n");

	PRLOG("%s %d %d", value, offset, len);

	send_udp_msg(value);

done:
	PRLOG("done");
	gatt_db_attribute_write_result(attrib, id, error);
}


static void gap_device_wifi_turn_off_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t error = 0;
	size_t len = 0;
	const uint8_t *value = NULL;

	PRLOG("GAP WiFi Errors Read called\n");

	len = server->wifi_error_len;

	if (offset > len) {
		error = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	len -= offset;
	value = len ? &server->wifi_error[offset] : NULL;

done:
	gatt_db_attribute_read_result(attrib, id, error, value, len);
}

static void gap_device_wifi_turn_off_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	PRLOG("GAP WiFi Turn off Write called\n");

	system("sudo nmcli radio wifi off");

	PRLOG("done");
}

static void gap_device_name_ext_prop_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	uint8_t value[2];

	PRLOG("Device Name Extended Properties Read called\n");

	value[0] = BT_GATT_CHRC_EXT_PROP_RELIABLE_WRITE;
	value[1] = 0;

	gatt_db_attribute_read_result(attrib, id, 0, value, sizeof(value));
}

static void gatt_service_changed_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	PRLOG("Service Changed Read called\n");

	gatt_db_attribute_read_result(attrib, id, 0, NULL, 0);
}

static void gatt_svc_chngd_ccc_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t value[2];

	PRLOG("Service Changed CCC Read called\n");

	value[0] = server->svc_chngd_enabled ? 0x02 : 0x00;
	value[1] = 0x00;

	gatt_db_attribute_read_result(attrib, id, 0, value, sizeof(value));
}

static void gatt_svc_chngd_ccc_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t ecode = 0;

	PRLOG("Service Changed CCC Write called\n");

	if (!value || len != 2) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (value[0] == 0x00)
		server->svc_chngd_enabled = false;
	else if (value[0] == 0x02)
		server->svc_chngd_enabled = true;
	else
		ecode = 0x80;

	PRLOG("Service Changed Enabled: %s\n",
				server->svc_chngd_enabled ? "true" : "false");

done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}

static void hr_msrmt_ccc_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t value[2];

	value[0] = server->hr_msrmt_enabled ? 0x01 : 0x00;
	value[1] = 0x00;

	gatt_db_attribute_read_result(attrib, id, 0, value, 2);
}

static bool hr_msrmt_cb(void *user_data)
{
	struct server *server = user_data;
	bool expended_present = !(server->hr_ee_count % 10);
	uint16_t len = 2;
	uint8_t pdu[4];
	uint32_t cur_ee;

	pdu[0] = 0x06;
	pdu[1] = 90 + (rand() % 40);

	if (expended_present) {
		pdu[0] |= 0x08;
		put_le16(server->hr_energy_expended, pdu + 2);
		len += 2;
	}

	bt_gatt_server_send_notification(server->gatt,
						server->hr_msrmt_handle,
						pdu, len);


	cur_ee = server->hr_energy_expended;
	server->hr_energy_expended = MIN(UINT16_MAX, cur_ee + 10);
	server->hr_ee_count++;

	return true;
}

static void update_hr_msrmt_simulation(struct server *server)
{
	if (!server->hr_msrmt_enabled || !server->hr_visible) {
		timeout_remove(server->hr_timeout_id);
		return;
	}

	server->hr_timeout_id = timeout_add(1000, hr_msrmt_cb, server, NULL);
}

static void hr_msrmt_ccc_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t ecode = 0;

	if (!value || len != 2) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (value[0] == 0x00)
		server->hr_msrmt_enabled = false;
	else if (value[0] == 0x01) {
		if (server->hr_msrmt_enabled) {
			PRLOG("HR Measurement Already Enabled\n");
			goto done;
		}

		server->hr_msrmt_enabled = true;
	} else
		ecode = 0x80;

	PRLOG("HR: Measurement Enabled: %s\n",
				server->hr_msrmt_enabled ? "true" : "false");

	update_hr_msrmt_simulation(server);

done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}

static void hr_control_point_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t ecode = 0;

	if (!value || len != 1) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (value[0] == 1) {
		PRLOG("HR: Energy Expended value reset\n");
		server->hr_energy_expended = 0;
	}

done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}

static void confirm_write(struct gatt_db_attribute *attr, int err,
							void *user_data)
{
	if (!err)
		return;

	fprintf(stderr, "Error caching attribute %p - err: %d\n", attr, err);
	exit(1);
}

static void populate_gap_service(struct server *server)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *service, *tmp;
	uint16_t appearance;

	/* Add the GAP service */
	bt_uuid16_create(&uuid, UUID_GAP);
	service = gatt_db_add_service(server->db, &uuid, true, 14);

	/*
	 * Device Name characteristic. Make the value dynamically read and
	 * written via callbacks.
	 */
	bt_uuid16_create(&uuid, GATT_CHARAC_DEVICE_NAME);
	gatt_db_service_add_characteristic(service, &uuid,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
					BT_GATT_CHRC_PROP_READ |
					BT_GATT_CHRC_PROP_EXT_PROP,
					gap_device_name_read_cb,
					gap_device_name_write_cb,
					server);

	// bt_uuid16_create(&uuid, GATT_CHARAC_EXT_PROPER_UUID);
	// gatt_db_service_add_descriptor(service, &uuid, BT_ATT_PERM_READ,
	// 				gap_device_name_ext_prop_read_cb,
	// 				NULL, server);

	/*
	 * Appearance characteristic. Reads and writes should obtain the value
	 * from the database.
	 */
	bt_uuid16_create(&uuid, GATT_CHARAC_APPEARANCE);
	tmp = gatt_db_service_add_characteristic(service, &uuid,
							BT_ATT_PERM_READ,
							BT_GATT_CHRC_PROP_READ,
							NULL, NULL, server);

	/*
	 * Write the appearance value to the database, since we're not using a
	 * callback.
	 */
	put_le16(128, &appearance);
	gatt_db_attribute_write(tmp, 0, (void *) &appearance,
							sizeof(appearance),
							BT_ATT_OP_WRITE_REQ,
							NULL, confirm_write,
							NULL);

	/*
	 * WiFi Name characteristic. Make the value dynamically read and
	 * written via callbacks.
	 */
	bt_uuid16_create(&uuid, GATT_CHARAC_WIFI_NAME);
	gatt_db_service_add_characteristic(service, &uuid,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
					BT_GATT_CHRC_PROP_NOTIFY | BT_GATT_CHRC_PROP_INDICATE | BT_GATT_CHRC_PROP_READ |
					BT_GATT_CHRC_PROP_WRITE |
					BT_GATT_CHRC_PROP_EXT_PROP,
					gap_device_wifi_read_cb,
					gap_device_wifi_write_cb,
					server);

	gatt_db_service_set_active(service, true);

			/*
	 * WiFi Password characteristic. Make the value dynamically read and
	 * written via callbacks.
	 */
	bt_uuid16_create(&uuid, GATT_CHARAC_WIFI_PASSWORD);
	gatt_db_service_add_characteristic(service, &uuid,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
					BT_GATT_CHRC_PROP_READ |
					BT_GATT_CHRC_PROP_WRITE |
					BT_GATT_CHRC_PROP_EXT_PROP,
					gap_device_wifi_password_read_cb,
					gap_device_wifi_password_write_cb,
					server);

	/*
	 * WiFi List characteristic. Make the value dynamically read and
	 * written via callbacks.
	 */
	bt_uuid16_create(&uuid, GATT_CHARAC_WIFI_LIST);
	gatt_db_service_add_characteristic(service, &uuid,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
					BT_GATT_CHRC_PROP_READ |
					BT_GATT_CHRC_PROP_WRITE |
					BT_GATT_CHRC_PROP_EXT_PROP,
					gap_device_wifi_list_read_cb,
					gap_device_wifi_list_write_cb,
					server);


	/*
	 * WiFi Turning off characteristic. Make the value dynamically read and
	 * written via callbacks.
	 */
	bt_uuid16_create(&uuid, GATT_CHARAC_TURN_OFF_WIFI);
	tmp = gatt_db_service_add_characteristic(service, &uuid,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
					BT_GATT_CHRC_PROP_READ |
					BT_GATT_CHRC_PROP_WRITE |
					BT_GATT_CHRC_PROP_EXT_PROP | BT_GATT_CHRC_PROP_NOTIFY | BT_GATT_CHRC_PROP_INDICATE,
					gap_device_wifi_turn_off_read_cb,
					gap_device_wifi_turn_off_write_cb,
					server);

	bt_uuid16_create(&uuid, GATT_CHARAC_PILOTING_MESSAGE);
	gatt_db_service_add_characteristic(service, &uuid,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
					BT_GATT_CHRC_PROP_READ |
					BT_GATT_CHRC_PROP_WRITE |
					BT_GATT_CHRC_PROP_EXT_PROP | BT_GATT_CHRC_PROP_NOTIFY | BT_GATT_CHRC_PROP_INDICATE,
					gap_device_piloting_message_read_cb,
					gap_device_piloting_message_write_cb,
					server);

	bt_uuid16_create(&uuid, GATT_CHARAC_EXT_PROPER_UUID_2);
	gatt_db_service_add_descriptor(service, &uuid, BT_ATT_PERM_READ | BT_ATT_PERM_WRITE |
					BT_GATT_CHRC_PROP_READ |
					BT_GATT_CHRC_PROP_WRITE |
					BT_GATT_CHRC_PROP_EXT_PROP | BT_GATT_CHRC_PROP_NOTIFY | BT_GATT_CHRC_PROP_INDICATE,
					gap_device_name_ext_prop_read_cb,
					NULL, server);

	server->wifi_turned_off = gatt_db_attribute_get_handle(tmp);

	printf("handle = %#04x", server->wifi_turned_off);

	gatt_db_service_set_active(service, true);
}

static void populate_gatt_service(struct server *server)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *service, *svc_chngd;

	/* Add the GATT service */
	bt_uuid16_create(&uuid, UUID_GATT);
	service = gatt_db_add_service(server->db, &uuid, true, 4);

	bt_uuid16_create(&uuid, GATT_CHARAC_SERVICE_CHANGED);
	svc_chngd = gatt_db_service_add_characteristic(service, &uuid,
			BT_ATT_PERM_READ,
			BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_INDICATE,
			gatt_service_changed_cb,
			NULL, server);
	server->gatt_svc_chngd_handle = gatt_db_attribute_get_handle(svc_chngd);

	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	gatt_db_service_add_descriptor(service, &uuid,
				BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
				gatt_svc_chngd_ccc_read_cb,
				gatt_svc_chngd_ccc_write_cb, server);

	gatt_db_service_set_active(service, true);
}

static void populate_hr_service(struct server *server)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *service, *hr_msrmt, *body;
	uint8_t body_loc = 1;  /* "Chest" */

	/* Add Heart Rate Service */
	bt_uuid16_create(&uuid, UUID_HEART_RATE);
	service = gatt_db_add_service(server->db, &uuid, true, 8);
	server->hr_handle = gatt_db_attribute_get_handle(service);

	/* HR Measurement Characteristic */
	bt_uuid16_create(&uuid, UUID_HEART_RATE_MSRMT);
	hr_msrmt = gatt_db_service_add_characteristic(service, &uuid,
						BT_ATT_PERM_NONE,
						BT_GATT_CHRC_PROP_NOTIFY,
						NULL, NULL, NULL);
	server->hr_msrmt_handle = gatt_db_attribute_get_handle(hr_msrmt);

	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	gatt_db_service_add_descriptor(service, &uuid,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
					hr_msrmt_ccc_read_cb,
					hr_msrmt_ccc_write_cb, server);

	/*
	 * Body Sensor Location Characteristic. Make reads obtain the value from
	 * the database.
	 */
	bt_uuid16_create(&uuid, UUID_HEART_RATE_BODY);
	body = gatt_db_service_add_characteristic(service, &uuid,
						BT_ATT_PERM_READ,
						BT_GATT_CHRC_PROP_READ,
						NULL, NULL, server);
	gatt_db_attribute_write(body, 0, (void *) &body_loc, sizeof(body_loc),
							BT_ATT_OP_WRITE_REQ,
							NULL, confirm_write,
							NULL);

	/* HR Control Point Characteristic */
	bt_uuid16_create(&uuid, UUID_HEART_RATE_CTRL);
	gatt_db_service_add_characteristic(service, &uuid,
						BT_ATT_PERM_WRITE,
						BT_GATT_CHRC_PROP_WRITE,
						NULL, hr_control_point_write_cb,
						server);

	if (server->hr_visible)
		gatt_db_service_set_active(service, true);
}

static void populate_db(struct server *server)
{
	populate_gap_service(server);
	populate_gatt_service(server);
	populate_hr_service(server);
}

static struct server *server_create(int fd, uint16_t mtu, bool hr_visible)
{
	struct server *server;
	size_t name_len = strlen(test_device_name);

	size_t wifi_len = strlen(test_wifi_name);

	server = new0(struct server, 1);
	if (!server) {
		fprintf(stderr, "Failed to allocate memory for server\n");
		return NULL;
	}

	server->att = bt_att_new(fd, false);
	if (!server->att) {
		fprintf(stderr, "Failed to initialze ATT transport layer\n");
		goto fail;
	}

	if (!bt_att_set_close_on_unref(server->att, true)) {
		fprintf(stderr, "Failed to set up ATT transport layer\n");
		goto fail;
	}

	if (!bt_att_register_disconnect(server->att, att_disconnect_cb, NULL,
									NULL)) {
		fprintf(stderr, "Failed to set ATT disconnect handler\n");
		goto fail;
	}

//todo for wifi?
	server->name_len = name_len + 1;
	server->device_name = malloc(name_len + 1);
	if (!server->device_name) {
		fprintf(stderr, "Failed to allocate memory for device name\n");
		goto fail;
	}

	memcpy(server->device_name, test_device_name, name_len);
	server->device_name[name_len] = '\0';


	server->wifi_len = wifi_len + 1;
	server->wifi_name = malloc(wifi_len + 1);
	if (!server->wifi_name) {
		fprintf(stderr, "Failed to allocate memory for wifi name\n");
		goto fail;
	}

	memcpy(server->wifi_name, test_wifi_name, wifi_len);
	server->wifi_name[wifi_len] = '\0';


	server->fd = fd;
	server->db = gatt_db_new();
	if (!server->db) {
		fprintf(stderr, "Failed to create GATT database\n");
		goto fail;
	}

	server->gatt = bt_gatt_server_new(server->db, server->att, mtu, 0);
	if (!server->gatt) {
		fprintf(stderr, "Failed to create GATT server\n");
		goto fail;
	}

	server->hr_visible = hr_visible;

	if (verbose) {
		bt_att_set_debug(server->att, att_debug_cb, "att: ", NULL);
		bt_gatt_server_set_debug(server->gatt, gatt_debug_cb,
							"server: ", NULL);
	}

	/* Random seed for generating fake Heart Rate measurements */
	srand(time(NULL));

	/* bt_gatt_server already holds a reference */
	populate_db(server);

	return server;

fail:
	gatt_db_unref(server->db);
	free(server->device_name);
	free(server->wifi_name);
	bt_att_unref(server->att);
	free(server);

	return NULL;
}

static void server_destroy(struct server *server)
{
	timeout_remove(server->hr_timeout_id);
	bt_gatt_server_unref(server->gatt);
	gatt_db_unref(server->db);
}

static void usage(void)
{
	printf("btgatt-server\n");
	printf("Usage:\n\tbtgatt-server [options]\n");

	printf("Options:\n"
		"\t-i, --index <id>\t\tSpecify adapter index, e.g. hci0\n"
		"\t-m, --mtu <mtu>\t\t\tThe ATT MTU to use\n"
		"\t-s, --security-level <sec>\tSet security level (low|"
								"medium|high)\n"
		"\t-t, --type [random|public] \t The source address type\n"
		"\t-v, --verbose\t\t\tEnable extra logging\n"
		"\t-r, --heart-rate\t\tEnable Heart Rate service\n"
		"\t-h, --help\t\t\tDisplay help\n");
}

static struct option main_options[] = {
	{ "index",		1, 0, 'i' },
	{ "mtu",		1, 0, 'm' },
	{ "security-level",	1, 0, 's' },
	{ "type",		1, 0, 't' },
	{ "verbose",		0, 0, 'v' },
	{ "heart-rate",		0, 0, 'r' },
	{ "help",		0, 0, 'h' },
	{ }
};

static int l2cap_le_att_listen_and_accept(bdaddr_t *src, int sec,
							uint8_t src_type)
{
	int sk, nsk;
	struct sockaddr_l2 srcaddr, addr;
	socklen_t optlen;
	struct bt_security btsec;
	char ba[18];

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		perror("Failed to create L2CAP socket");
		return -1;
	}

	/* Set up source address */
	memset(&srcaddr, 0, sizeof(srcaddr));
	srcaddr.l2_family = AF_BLUETOOTH;
	srcaddr.l2_cid = htobs(ATT_CID);
	srcaddr.l2_bdaddr_type = src_type;
	bacpy(&srcaddr.l2_bdaddr, src);

	if (bind(sk, (struct sockaddr *) &srcaddr, sizeof(srcaddr)) < 0) {
		perror("Failed to bind L2CAP socket");
		goto fail;
	}

	/* Set the security level */
	memset(&btsec, 0, sizeof(btsec));
	btsec.level = sec;
	if (setsockopt(sk, SOL_BLUETOOTH, BT_SECURITY, &btsec,
							sizeof(btsec)) != 0) {
		fprintf(stderr, "Failed to set L2CAP security level\n");
		goto fail;
	}

	if (listen(sk, 10) < 0) {
		perror("Listening on socket failed");
		goto fail;
	}

	printf("Started listening on ATT channel. Waiting for connections\n");

	memset(&addr, 0, sizeof(addr));
	optlen = sizeof(addr);
	nsk = accept(sk, (struct sockaddr *) &addr, &optlen);
	if (nsk < 0) {
		perror("Accept failed");
		goto fail;
	}

	ba2str(&addr.l2_bdaddr, ba);
	printf("Connect from %s\n", ba);
	close(sk);

	return nsk;

fail:
	close(sk);
	return -1;
}

static void notify_usage(void)
{
	printf("Usage: notify [options] <value_handle> <value>\n"
					"Options:\n"
					"\t -i, --indicate\tSend indication\n"
					"e.g.:\n"
					"\tnotify 0x0001 00 01 00\n");
}

static struct option notify_options[] = {
	{ "indicate",	0, 0, 'i' },
	{ }
};

static bool parse_args(char *str, int expected_argc,  char **argv, int *argc)
{
	char **ap;

	for (ap = argv; (*ap = strsep(&str, " \t")) != NULL;) {
		if (**ap == '\0')
			continue;

		(*argc)++;
		ap++;

		if (*argc > expected_argc)
			return false;
	}

	return true;
}


static void cmd_notify(struct server *server, char *cmd_str)
{
	int opt, i;
	char *argvbuf[516];
	char **argv = argvbuf;
	int argc = 1;
	uint16_t handle;
	char *endptr = NULL;
	int length;
	uint8_t *value = NULL;
	bool indicate = false;

	if (!parse_args(cmd_str, 514, argv + 1, &argc)) {
		printf("Too many arguments\n");
		notify_usage();
		return;
	}

	optind = 0;
	argv[0] = "notify";
	while ((opt = getopt_long(argc, argv, "+i", notify_options,
								NULL)) != -1) {
		switch (opt) {
		case 'i':
			indicate = true;
			break;
		default:
			notify_usage();
			return;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		notify_usage();
		return;
	}

	handle = strtol(argv[0], &endptr, 16);
	if (!endptr || *endptr != '\0' || !handle) {
		printf("Invalid handle: %s\n", argv[0]);
		return;
	}

	length = argc - 1;

	if (length > 0) {
		if (length > UINT16_MAX) {
			printf("Value too long\n");
			return;
		}

		value = malloc(length);
		if (!value) {
			printf("Failed to construct value\n");
			return;
		}

		for (i = 1; i < argc; i++) {
			if (strlen(argv[i]) != 2) {
				printf("Invalid value byte: %s\n",
								argv[i]);
				goto done;
			}

			value[i-1] = strtol(argv[i], &endptr, 16);
			if (endptr == argv[i] || *endptr != '\0'
							|| errno == ERANGE) {
				printf("Invalid value byte: %s\n",
								argv[i]);
				goto done;
			}
		}
	}

	if (indicate) {
		if (!bt_gatt_server_send_indication(server->gatt, handle,
							value, length,
							conf_cb, NULL, NULL))
			printf("Failed to initiate indication\n");
	} else if (!bt_gatt_server_send_notification(server->gatt, handle,
								value, length))
		printf("Failed to initiate notification\n");
	else
	{
		printf("OK to initiate notification\n, %x, %d, %d", handle,
								value, length);
	}
	

done:
	free(value);
}

static void heart_rate_usage(void)
{
	printf("Usage: heart-rate on|off\n");
}


static struct server *server;
static uint8_t *value = NULL;


static void cmd_heart_rate(struct server *server, char *cmd_str)
{
	bool enable;
	uint8_t pdu[4];
	struct gatt_db_attribute *attr;

	if (!cmd_str) {
		heart_rate_usage();
		return;
	}

	if (strcmp(cmd_str, "on") == 0)
		enable = true;
	else if (strcmp(cmd_str, "off") == 0)
		enable = false;
	else {
		heart_rate_usage();
		return;
	}

	if (enable == server->hr_visible) {
		printf("Heart Rate Service already %s\n",
						enable ? "visible" : "hidden");
		return;
	}

	server->hr_visible = enable;
	attr = gatt_db_get_attribute(server->db, server->hr_handle);
	gatt_db_service_set_active(attr, server->hr_visible);
	update_hr_msrmt_simulation(server);

	if (!server->svc_chngd_enabled)
		return;

	put_le16(server->hr_handle, pdu);
	put_le16(server->hr_handle + 7, pdu + 2);

	server->hr_msrmt_enabled = false;
	update_hr_msrmt_simulation(server);

	bt_gatt_server_send_indication(server->gatt,
						server->gatt_svc_chngd_handle,
						pdu, 4, conf_cb, NULL, NULL);
}

static void print_uuid(const bt_uuid_t *uuid)
{
	char uuid_str[MAX_LEN_UUID_STR];
	bt_uuid_t uuid128;

	bt_uuid_to_uuid128(uuid, &uuid128);
	bt_uuid_to_string(&uuid128, uuid_str, sizeof(uuid_str));

	printf("%s\n", uuid_str);
}

static void print_incl(struct gatt_db_attribute *attr, void *user_data)
{
	struct server *server = user_data;
	uint16_t handle, start, end;
	struct gatt_db_attribute *service;
	bt_uuid_t uuid;

	if (!gatt_db_attribute_get_incl_data(attr, &handle, &start, &end))
		return;

	service = gatt_db_get_attribute(server->db, start);
	if (!service)
		return;

	gatt_db_attribute_get_service_uuid(service, &uuid);

	printf("\t  " COLOR_GREEN "include" COLOR_OFF " - handle: "
					"0x%04x, - start: 0x%04x, end: 0x%04x,"
					"uuid: ", handle, start, end);
	print_uuid(&uuid);
}

static void print_desc(struct gatt_db_attribute *attr, void *user_data)
{
	printf("\t\t  " COLOR_MAGENTA "descr" COLOR_OFF
					" - handle: 0x%04x, uuid: ",
					gatt_db_attribute_get_handle(attr));
	print_uuid(gatt_db_attribute_get_type(attr));
}

static void print_chrc(struct gatt_db_attribute *attr, void *user_data)
{
	uint16_t handle, value_handle;
	uint8_t properties;
	uint16_t ext_prop;
	bt_uuid_t uuid;

	if (!gatt_db_attribute_get_char_data(attr, &handle,
								&value_handle,
								&properties,
								&ext_prop,
								&uuid))
		return;

	printf("\t  " COLOR_YELLOW "charac" COLOR_OFF
				" - start: 0x%04x, value: 0x%04x, "
				"props: 0x%02x, ext_prop: 0x%04x, uuid: ",
				handle, value_handle, properties, ext_prop);
	print_uuid(&uuid);

	gatt_db_service_foreach_desc(attr, print_desc, NULL);
}

static void print_service(struct gatt_db_attribute *attr, void *user_data)
{
	struct server *server = user_data;
	uint16_t start, end;
	bool primary;
	bt_uuid_t uuid;

	if (!gatt_db_attribute_get_service_data(attr, &start, &end, &primary,
									&uuid))
		return;

	printf(COLOR_RED "service" COLOR_OFF " - start: 0x%04x, "
				"end: 0x%04x, type: %s, uuid: ",
				start, end, primary ? "primary" : "secondary");
	print_uuid(&uuid);

	gatt_db_service_foreach_incl(attr, print_incl, server);
	gatt_db_service_foreach_char(attr, print_chrc, NULL);

	printf("\n");
}

static void cmd_services(struct server *server, char *cmd_str)
{
	gatt_db_foreach_service(server->db, NULL, print_service, server);
}

static bool convert_sign_key(char *optarg, uint8_t key[16])
{
	int i;

	if (strlen(optarg) != 32) {
		printf("sign-key length is invalid\n");
		return false;
	}

	for (i = 0; i < 16; i++) {
		if (sscanf(optarg + (i * 2), "%2hhx", &key[i]) != 1)
			return false;
	}

	return true;
}

static void set_sign_key_usage(void)
{
	printf("Usage: set-sign-key [options]\nOptions:\n"
		"\t -c, --sign-key <remote csrk>\tRemote CSRK\n"
		"e.g.:\n"
		"\tset-sign-key -c D8515948451FEA320DC05A2E88308188\n");
}

static bool remote_counter(uint32_t *sign_cnt, void *user_data)
{
	static uint32_t cnt = 0;

	if (*sign_cnt < cnt)
		return false;

	cnt = *sign_cnt;

	return true;
}

static void cmd_set_sign_key(struct server *server, char *cmd_str)
{
	char *argv[3];
	int argc = 0;
	uint8_t key[16];

	memset(key, 0, 16);

	if (!parse_args(cmd_str, 2, argv, &argc)) {
		set_sign_key_usage();
		return;
	}

	if (argc != 2) {
		set_sign_key_usage();
		return;
	}

	if (!strcmp(argv[0], "-c") || !strcmp(argv[0], "--sign-key")) {
		if (convert_sign_key(argv[1], key))
			bt_att_set_remote_key(server->att, key, remote_counter,
									server);
	} else
		set_sign_key_usage();
}

static void cmd_help(struct server *server, char *cmd_str);

typedef void (*command_func_t)(struct server *server, char *cmd_str);

static struct {
	char *cmd;
	command_func_t func;
	char *doc;
} command[] = {
	{ "help", cmd_help, "\tDisplay help message" },
	{ "notify", cmd_notify, "\tSend handle-value notification" },
	{ "heart-rate", cmd_heart_rate, "\tHide/Unhide Heart Rate Service" },
	{ "services", cmd_services, "\tEnumerate all services" },
	{ "set-sign-key", cmd_set_sign_key,
			"\tSet remote signing key for signed write command"},
	{ }
};

static void cmd_help(struct server *server, char *cmd_str)
{
	int i;

	printf("Commands:\n");
	for (i = 0; command[i].cmd; i++)
		printf("\t%-15s\t%s\n", command[i].cmd, command[i].doc);
}

static void prompt_read_cb(int fd, uint32_t events, void *user_data)
{
	ssize_t read;
	size_t len = 0;
	char *line = NULL;
	char *cmd = NULL, *args;
	struct server *server = user_data;
	int i;

	if (events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
		mainloop_quit();
		return;
	}

	read = getline(&line, &len, stdin);
	if (read < 0)
		return;

	if (read <= 1) {
		cmd_help(server, NULL);
		print_prompt();
		return;
	}

	line[read-1] = '\0';
	args = line;

	while ((cmd = strsep(&args, " \t")))
		if (*cmd != '\0')
			break;

	if (!cmd)
		goto failed;

	for (i = 0; command[i].cmd; i++) {
		if (strcmp(command[i].cmd, cmd) == 0)
			break;
	}

	if (command[i].cmd)
		command[i].func(server, args);
	else
		fprintf(stderr, "Unknown command: %s\n", line);

failed:
	print_prompt();

	free(line);
}



static void prompt_read_cb_wifi(int fd, uint32_t events, void *user_data)
{
	ssize_t read;
	size_t len = 0;
	char *line = NULL;
	char *cmd = NULL, *args;
	struct server *server = user_data;
	int i;

	printf("events = %d", events);

	if (events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR | EPOLLIN)) {
		printf("here %d", events);
		mainloop_quit();
		return;
	}

	read = getline(&line, &len, stdin);
	if (read < 0)
	{
		printf("here bla", events);
		return;
	}

	if (read <= 1) {
		cmd_help(server, NULL);
		print_prompt();
		return;
	}

	line[read-1] = '\0';
	args = line;

	while ((cmd = strsep(&args, " \t")))
		if (*cmd != '\0')
			break;

	if (!cmd)
		goto failed;

	for (i = 0; command[i].cmd; i++) {
		if (strcmp(command[i].cmd, cmd) == 0)
			break;
	}

	if (command[i].cmd)
		command[i].func(server, args);
	else
		fprintf(stderr, "Unknown command: %s\n", line);

failed:
	print_prompt();

	free(line);
}

static void signal_cb(int signum, void *user_data)
{
	switch (signum) {
	case SIGINT:
	case SIGTERM:
		mainloop_quit();
		break;
	default:
		break;
	}
}

struct hci_request ble_hci_request(uint16_t ocf, int clen, void * status, void * cparam)
{
	struct hci_request rq;
	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = ocf;
	rq.cparam = cparam;
	rq.clen = clen;
	rq.rparam = status;
	rq.rlen = 1;
	return rq;
}

static void* send_wifi_error_notification(void* arg )
{
	printf("1 initiate notification\n");

    int sockfd;
    struct sockaddr_in sockserver;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
            perror("cannot create socket\n");
    }

    memset(&sockserver, 0, sizeof(sockserver));
    sockserver.sin_family = AF_INET;
    sockserver.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &(sockserver.sin_addr));

    //if(bind(sockfd, (struct sockaddr *) &server, sizeof(server)) < 0) {
    //        perror("bind failed\n");
    //}


	int yes = 1;

	int tcp_keepcnt = 2;
	int tcp_keepidle = 5;
	int tcp_keepintvl = 5;

	setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &tcp_keepcnt, sizeof(tcp_keepcnt));
	setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &tcp_keepidle, sizeof(tcp_keepidle));
	setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &tcp_keepintvl, sizeof(tcp_keepintvl));

	int retval = setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE,
                &yes, sizeof(yes));
    if (retval == -1) {
        printf("ERROR setsockopt\n");
    }

	// retval = bind(sockfd, (struct sockaddr *) &sockserver,
    //         sizeof(sockserver));
    // if (retval == -1) {
	// 	printf("ERROR setsockopt 2\n");
    // }

	while (mainloop_add_fd(sockfd,   EPOLLIN |
    //EPOLLPRI |
    EPOLLOUT |
   // EPOLLRDNORM | 
   // EPOLLRDBAND |
   // EPOLLWRNORM |
   // EPOLLWRBAND |
   // EPOLLMSG |
    EPOLLERR |
    EPOLLHUP |
  	EPOLLRDHUP | 
   // EPOLLEXCLUSIVE | 
   // EPOLLWAKEUP |
   // EPOLLONESHOT |
    EPOLLET, prompt_read_cb_wifi, server, NULL) < 0) {
		printf("Failed to add listen socket for wifi\n");
		sleep(5);
		close(sockfd);

		if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
					perror("cannot create socket\n");
			}

		setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &tcp_keepcnt, sizeof(tcp_keepcnt));
		setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &tcp_keepidle, sizeof(tcp_keepidle));
		setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &tcp_keepintvl, sizeof(tcp_keepintvl));

		int retval = setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE,
					&yes, sizeof(yes));
		if (retval == -1) {
			printf("ERROR setsockopt\n");
		}
		//netcfg_state = 0;
		//return NULL;
	}

	// while(true)
	// {
	// 	if (!bt_gatt_server_send_notification(server->gatt, server->wifi_turned_off, 5, 4))
	// 	{
	// 		printf("Failed to initiate notification\n");
	// 	}
	// 	else
	// 	{
	// 		printf("OK to initiate notification\n");
	// 	}

		//if( sendto(sockfd, "ping", 4, EPOLLERR, (struct sockaddr *) &sockserver, sizeof(sockserver)) < 0)
		//{
		//	printf("ERROR setsockopt 3\n");
			//write(sockfd, EPOLLERR, sizeof(EPOLLERR));
			//break;
			// if (!bt_gatt_server_send_notification(server->gatt, server->wifi_turned_off, 5, 1))
			// {
			// 	printf("Failed to initiate notification\n");
			// }
			// else
			// {
			// 	printf("OK to initiate notification\n");
			// }
		//}
	//}	
}

void reverse_mac_address(char *data, size_t n)
{
    size_t i;

    for (i=0; i < n/2; i+=3) {
        int tmp = data[i];
		int tmp2 = data[i+1];
        data[i] = data[n - 1 - i - 1];
		data[i+1] = data[n - 1 - i];
        data[n - 1 - i - 1] = tmp;
		data[n - 1 - i] = tmp2;
    }
}

int run()
{

	while(true)
	{
		bdaddr_t src_addr;
		int dev_id = 0;
		int fd;
		int sec = BT_SECURITY_LOW;
		uint8_t src_type = BDADDR_LE_PUBLIC;
		uint16_t mtu = 0;
		sigset_t mask;
		bool hr_visible = false;

		if (dev_id == -1)
			bacpy(&src_addr, BDADDR_ANY);
		else if (hci_devba(dev_id, &src_addr) < 0) {
			perror("Adapter not available");
			return EXIT_FAILURE;
		}

		int hciDeviceId = hci_get_route(NULL);
		int hciSocket = hci_open_dev(hciDeviceId);
		int status = 0; 

		char* mac_bt;
		mac_bt = batostr(&src_addr);

		reverse_mac_address(mac_bt, 17);

		printf("robot device mac address = %s \n", mac_bt);

		le_set_advertising_data_cp adv_data_cp = ble_hci_params_for_set_adv_data(mac_bt);
		
		struct hci_request adv_data_rq = ble_hci_request(
			OCF_LE_SET_ADVERTISING_DATA,
			LE_SET_ADVERTISING_DATA_CP_SIZE, &status, &adv_data_cp);

		int ret = hci_send_req(hciSocket, &adv_data_rq, 1000);
		if ( ret < 0 ) {
			//hci_close_dev(dev_id);
			fprintf(stderr, "Failed to set advertising data. ret = %d, hciSocket = %d", ret, hciSocket);
			//return 0;
		}
			
		int res = hci_le_set_advertise_enable(hciSocket, 1, 1000);
		printf("advertise is enabled %d \n", res);

		fd = l2cap_le_att_listen_and_accept(&src_addr, sec, src_type);
		if (fd < 0) {
			fprintf(stderr, "Failed to accept L2CAP ATT connection\n");
			//return EXIT_FAILURE;
		}

		mainloop_init();

		server = server_create(fd, mtu, hr_visible);
		if (!server) {
			close(fd);
			//return EXIT_FAILURE;
		}

		if (mainloop_add_fd(fileno(stdin),
					EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR,
					prompt_read_cb, server, NULL) < 0) {
			fprintf(stderr, "Failed to initialize console\n");
			server_destroy(server);

			//return EXIT_FAILURE;
		}

		//int netcfg_state = 1;
		//int sfd = socket(AF_INET, SOCK_STREAM, 0);

		//int err;
		//pthread_t tid;

		//pthread_attr_t attr;
		//size_t stack_size = 16 * 1024;
		//int s = pthread_attr_init(&attr);

		//s = pthread_attr_setstacksize(&attr, stack_size);
		//if (s != 0)
		//	printf("\n ZHOPA created successfully\n");//handle_error_en(s, "pthread_attr_setstacksize");

		// err = pthread_create(&tid, NULL, &send_wifi_error_notification, NULL);
		// if (err != 0)
		// 	printf("\ncan't create thread :[%s]", strerror(err));
		// else
		// 	printf("\n Thread created successfully\n");

		// // void* resThread;

		// printf("\n Thread created successfully 2\n");
		
		// int s = pthread_detach(tid);

		// printf("\n Thread created successfully 3\n");

		/////////////


		printf("Running GATT server\n");

		// bt_gatt_server_send_notification(server->gatt,
		// 					 server->wifi_turned_off,
		// 					 0,
		// 					 0);

		sigemptyset(&mask);
		sigaddset(&mask, SIGINT);
		sigaddset(&mask, SIGTERM);

		mainloop_set_signal(&mask, signal_cb, NULL, NULL);

		print_prompt();

		mainloop_run();

		server_destroy(server);
	}

	//printf("\n Thread created successfully 4\n");



	//printf("\n\nShutting down...\n");

	//

	return EXIT_SUCCESS;
}

