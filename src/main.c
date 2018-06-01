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

#include <stdio.h>
#include <stdlib.h>
#include <ldap.h>
#include <errno.h>

#include "config_parser.h"
#include "drop_privileges.h"

struct ldap_context {
	/* config */
	struct config conf;

	/* basic ldap connection */
	int ldap_result;
	LDAP *ld;

	/* auth */
	struct berval *scred;

	/* search */
	char *search_filter;
	LDAPMessage *msg;

	/* search - iterate results */
	LDAPMessage *entry;
	char *attr;
	BerElement *ber;
	BerValue **values;
};

void ldap_context_init(struct ldap_context *ctx) {
	memset(ctx, 0, sizeof(struct ldap_context));
}

void ldap_context_free(struct ldap_context *ctx) {
	if (ctx->values != NULL) { ldap_value_free_len(ctx->values); }
	if (ctx->ber != NULL) { ber_free(ctx->ber, 0); }
	if (ctx->attr != NULL) { ldap_memfree(ctx->attr); }
	if (ctx->msg != NULL) { ldap_msgfree(ctx->msg); }
	if (ctx->search_filter != NULL) { free(ctx->search_filter); }
	/* TODO do we have to free scred (servercredp)? */
	if (ctx->ld != NULL) { ldap_unbind_ext_s(ctx->ld, NULL, NULL); }
}

void ldap_error(struct ldap_context *ctx) {
	int error = ctx->ldap_result;

	/* If our error code is LDAP_SUCCESS, then we may have been called after an API which sets ld_errno, so we'll
	 * attempt to read it. */
	if (error == LDAP_SUCCESS) {
		int temp;
		if ((temp = ldap_get_option(ctx->ld, LDAP_OPT_RESULT_CODE, &error)) != LDAP_OPT_SUCCESS) {
			fprintf(stderr, "ldap_error() called with success code, and failed to read LDAP_OPT_RESULT_CODE.\n");
			error = temp;
		}
	}

	fprintf(stderr, "%s\n", ldap_err2string(error));
	ldap_context_free(ctx);
	exit(error);
}

char *search_filter(char *uid) {
	/* 36 chars for base format + null */
	size_t len = 36 + strlen(uid);
	char *search_filter = malloc(len);
	memset(search_filter, '\0', len);
	snprintf(search_filter, len, "(&(objectClass=posixAccount)(uid=%s))", uid);
	return search_filter;
}

int main(int argc, char **argv) {
	/* Check for uid argument */
	if (argc != 2) {
		fprintf(stderr, "usage: %s <uid>\n", argv[0]);
		return -1;
	}

	/* The ldap_context contains all variables required for ldap, and aids in cleanup. */
	struct ldap_context ctx;
	ldap_context_init(&ctx);

	/* parse the config file */
	config_init(&ctx.conf);
	if (parse_config_file(&ctx.conf, "/etc/nslcd.conf") != 0) {
		perror("Unable to load /etc/nslcd.conf");
		return -2;
	}

	/* Drop root privileges */
	if (drop_privileges(ctx.conf.uid, ctx.conf.gid) != 0) {
		fprintf(stderr, "Failed to drop root privileges, aborting.\n");
		return -2;
	}

	/* Initialize LDAP. */
	if ((ctx.ldap_result = ldap_initialize(&ctx.ld, ctx.conf.uri)) != LDAP_SUCCESS) {
		ldap_error(&ctx);
	}

	/* Set LDAP protocol version. */
	/* TODO read version from config file */
	int ver = LDAP_VERSION3;
	if ((ctx.ldap_result = ldap_set_option(ctx.ld, LDAP_OPT_PROTOCOL_VERSION, &ver)) != LDAP_OPT_SUCCESS) {
		ldap_error(&ctx);
	}

	/* Setup password credentials. */
	struct berval cred;
	cred.bv_val = ctx.conf.bindpw;
	cred.bv_len = strlen(cred.bv_val);
	/* open ldap connection & authenticate */
	if ((ctx.ldap_result = ldap_sasl_bind_s(ctx.ld, ctx.conf.binddn, LDAP_SASL_SIMPLE, &cred, NULL, NULL,
			&ctx.scred)) != LDAP_SUCCESS) {
		ldap_error(&ctx);
	}

	/* Search directory for the uid given in argv[1].
	 * User must have an sshPublicKey attribute, else nothing is returned. */
	ctx.search_filter = search_filter(argv[1]);
	char *search_attrs[] = {"sshPublicKey", NULL};
	if ((ctx.ldap_result = ldap_search_ext_s(ctx.ld, ctx.conf.base, LDAP_SCOPE_SUBTREE, ctx.search_filter, search_attrs,
							0, NULL, NULL, NULL, LDAP_NO_LIMIT, &ctx.msg)) != LDAP_SUCCESS) {
		ldap_error(&ctx);
	}

	/* Get & Iterate search results. */
	if ((ctx.entry = ldap_first_entry(ctx.ld, ctx.msg)) == NULL) { ldap_error(&ctx); }
	for (; ctx.entry != NULL; ctx.entry = ldap_next_entry(ctx.ld, ctx.entry)) {

		/* Get & Iterate attributes */
		if ((ctx.attr = ldap_first_attribute(ctx.ld, ctx.entry, &ctx.ber)) == NULL) { ldap_error(&ctx); }
		for (; ctx.attr != NULL; ctx.attr = ldap_next_attribute(ctx.ld, ctx.entry, ctx.ber)) {

			/* Get & Iterate attribute values */
			if ((ctx.values = ldap_get_values_len(ctx.ld, ctx.entry, ctx.attr)) == NULL) { ldap_error(&ctx); }
			for (int i = 0; i < ldap_count_values_len(ctx.values); ++i) {
				/* This value has to be an entry for authorized keys, so just print it and continue. */
				printf("%s\n", ctx.values[i]->bv_val);
			}

			/* Free values memory */
			if (ctx.values != NULL) { ldap_value_free_len(ctx.values); ctx.values = NULL; }
		}

		/* Free attributes memory */
		if (ctx.ber != NULL) { ber_free(ctx.ber, 0); ctx.ber = NULL; }
		if (ctx.attr != NULL) { ldap_memfree(ctx.attr); ctx.attr = NULL; }
	}

	/* Free message memory */
	if (ctx.msg != NULL) { ldap_msgfree(ctx.msg); ctx.msg = NULL; }

	/* Free LDAP context */
	ldap_context_free(&ctx);

	return 0;
}
