#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <strings.h>
#include <ctype.h>
#include <memory.h>

#include "config_parser.h"

#define CONFIG_STATE_KEY_WS 0
#define CONFIG_STATE_KEY 1
#define CONFIG_STATE_VALUE_WS 2
#define CONFIG_STATE_VALUE 3

void config_init(struct config *conf) {
	conf->gid = "nobody";
	conf->uid = "nobody";
}

char *read_file(char *path, size_t *length) {
	char *buffer = NULL;
	FILE *f = fopen(path, "r");

	if (f != NULL) {
		fseek(f, 0, SEEK_END);
		long temp = ftell(f);
		*length = temp > 0 ? (size_t) temp : 0;
		fseek(f, 0, SEEK_SET);
		buffer = malloc(*length + 1);
		memset(buffer, '\0', *length + 1);

		if (buffer != NULL) {
			fread(buffer, 1, *length, f);
		}

		fclose(f);
	}

	return buffer;
}

char *parse_config_consume_whitespace(char *buffer) {
	for (; *buffer != '\0'; ++buffer) {
		if (isspace(*buffer) == 0) {
			break;
		}
	}

	return buffer;
}

char parse_config_extract_token(char **token, char **buffer, bool value) {
	char c = '\0';
	*token = *buffer;
	for (; **buffer != '\0'; ++(*buffer)) {
		if (value == 0 && isspace(**buffer) != 0) {
			c = **buffer;
			**buffer = '\0';
			++(*buffer);
			break;
		} else if (**buffer == '\n') {
			c = **buffer;
			**buffer = '\0';
			++(*buffer);
			break;
		}
	}

	return c;
}

uint8_t strcpy_allocate(char **dest, char *src) {
	if (src != NULL) {
		size_t len = strlen(src);
		*dest = malloc(len + 1);
		if (*dest != NULL) {
			memcpy(*dest, src, len);
			(*dest)[len] = '\0';
			return 0;
		}
	}

	return 1;
}

uint8_t parse_config_pair(struct config *conf, char *key, char *value) {
	if (strcasecmp("uri", key) == 0) {
		return strcpy_allocate(&conf->uri, value);
	}
	if (strcasecmp("base", key) == 0) {
		return strcpy_allocate(&conf->base, value);
	}
	if (strcasecmp("binddn", key) == 0) {
		return strcpy_allocate(&conf->binddn, value);
	}
	if (strcasecmp("bindpw", key) == 0) {
		return strcpy_allocate(&conf->bindpw, value);
	}

	return 1;
}

uint8_t parse_config(struct config *conf, char *buffer, size_t length) {
	uint8_t state = CONFIG_STATE_KEY_WS;
	char *key = NULL, *value = NULL, *cursor;
	char **token;

	for (cursor = buffer; *cursor != '\0'; cursor) {
		cursor = parse_config_consume_whitespace(cursor);

		switch (state) {
			default:
				continue;

			case CONFIG_STATE_KEY_WS:
				state = CONFIG_STATE_KEY;
				continue;

			case CONFIG_STATE_VALUE_WS:
				state = CONFIG_STATE_VALUE;
				continue;

			case CONFIG_STATE_KEY:
				token = &key;
				state = CONFIG_STATE_VALUE_WS;
				break;

			case CONFIG_STATE_VALUE:
				token = &value;
				state = CONFIG_STATE_KEY_WS;
				break;
		}

		char c = parse_config_extract_token(token, &cursor, token == &value);
		if (token == &key && !isblank(c)) {
			state = CONFIG_STATE_KEY_WS;
		}

		if (token == &value) {
			parse_config_pair(conf, key, value);
			key = NULL;
			value = NULL;
		}
	}

	return 0;
}

uint8_t parse_config_file(struct config *conf, char *path) {
	size_t length;
	char *buffer = read_file(path, &length);

	if (buffer != NULL) {
		if (parse_config(conf, buffer, length) == 0) {
			free(buffer);
			return 0;
		}
	}

	return 1;
}
