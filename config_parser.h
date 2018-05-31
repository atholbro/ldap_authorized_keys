#ifndef LDAP_AUTHORIZED_KEYS_CONFIG_PARSER_H
#define LDAP_AUTHORIZED_KEYS_CONFIG_PARSER_H

#include <stdint.h>
#include <stddef.h>

struct config {
	char *uri, *base, *binddn, *bindpw;
	char *uid, *gid;
};

void config_init(struct config *conf);
uint8_t parse_config(struct config *conf, char *buffer, size_t length);
uint8_t parse_config_file(struct config *conf, char *path);

#endif //LDAP_AUTHORIZED_KEYS_CONFIG_PARSER_H
