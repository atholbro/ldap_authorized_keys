/*
Copyright (c) 2018 Andrew Holbrook <atholbro@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

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
