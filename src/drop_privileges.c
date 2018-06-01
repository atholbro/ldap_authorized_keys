#include <unistd.h>
#include <grp.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include "drop_privileges.h"

/* See: https://wiki.sei.cmu.edu/confluence/display/c/POS36-C.+Observe+correct+revocation+order+while+relinquishing+privileges */

/* Returns nonzero if the two group lists are equivalent (taking into
   account that the lists may differ wrt the egid */
int eql_sups(const int cursups_size, const gid_t* const cursups_list,
			 const int targetsups_size, const gid_t* const targetsups_list) {
	int i;
	int j;
	const int n = targetsups_size;
	const int diff = cursups_size - targetsups_size;
	const gid_t egid = getegid();
	if (diff > 1 || diff < 0 ) {
		return 0;
	}
	for (i=0, j=0; i < n; i++, j++) {
		if (cursups_list[j] != targetsups_list[i]) {
			if (cursups_list[j] == egid) {
				i--; /* skipping j */
			} else {
				return 0;
			}
		}
	}
	/* If reached here, we're sure i==targetsups_size. Now, either
	   j==cursups_size (skipped the egid or it wasn't there), or we didn't
	   get to the egid yet because it's the last entry in cursups */
	return j == cursups_size ||
		   (j+1 == cursups_size && cursups_list[j] == egid);
}


/* Sets the suplimentary group list, returns 0 if successful  */
int set_sups(const int target_sups_size,const gid_t* const target_sups_list) {
#ifdef __FreeBSD__
	const int targetsups_size = target_sups_size + 1;
  gid_t* const targetsups_list = (gid_t* const) malloc(sizeof(gid_t) * targetsups_size);
  if (targetsups_list == NULL) {
    /* handle error */
  }
  memcpy(targetsups_list+1, target_sups_list, target_sups_size * sizeof(gid_t) );
  targetsups_list[0] = getegid();
#else
	const int targetsups_size = target_sups_size;
	const gid_t* const targetsups_list = target_sups_list;
#endif
	if (geteuid() == 0) { /* allowed to setgroups, let's not take any chances */
		if (-1 == setgroups(targetsups_size, targetsups_list)) {
			/* handle error */
		}
	} else {
		int cursups_size = getgroups( 0, NULL);
		gid_t* cursups_list = (gid_t*) malloc( sizeof(gid_t) * cursups_size);
		if (cursups_list == NULL) {
			/* handle error */
		}
		if (-1 == getgroups( cursups_size, cursups_list)) {
			/* handle error */
		}
		if (!eql_sups(cursups_size, cursups_list, targetsups_size, targetsups_list)) {
			if (-1 == setgroups(targetsups_size, targetsups_list)) { /* will probably fail... :( */
				/* handle error */
			}
		}
		free( cursups_list);
	}

#ifdef __FreeBSD__
	free( targetsups_list);
#endif
	return 0;
}

struct passwd *getuser(char *user) {
	struct passwd *result = NULL;

	/* First try to look up by uid, by converting the string to a long. */
	errno = 0;
	uid_t uid = (uid_t) strtoul(user, NULL, 10);

	/* If conversion to long fails, lookup user by name. Note: we consider 0 a fail, as that would be the root user. */
	if (errno != 0 || uid == 0) {
		errno = 0;
		if ((result = getpwnam(user)) == NULL) {
			perror("drop_privileges(): getpwnam()");
		}
	} else { /* lookup by uid */
		errno = 0;
		if ((result = getpwuid(uid)) == NULL) {
			perror("drop_privileges(): getpwuid()");
		}
	}

	return result;
}

int8_t drop_privileges(char *user, char *group) {
	/* Check if we already have root, by trying to set our uid to 0. If this fails, we're running as a user.
	 *
	 * Note that we set here rather then get, as getuid() will return the user's UID if the setuid bit is set on
	 * the binary. */
	if (setuid(0) != 0) {
		return 0;
	}

	// find target user
	struct passwd *pwd = getuser(user);
	if (pwd == NULL) {
		fprintf(stderr, "Failed to lookup user: %s in passwd.\n", user);
		return -2;
	}

	gid_t gid = pwd->pw_gid;
	if (setgid(gid) != 0) {
		perror("setgid");
		return -3;
	}
	set_sups(1, &gid);

	if (setuid(pwd->pw_uid) != 0) {
		perror("setuid");
		return -4;
	}

	if (setuid(0) == 0) {
		fprintf(stderr, "Able to regain root, aborting.\n");
		return -5;
	}

	return 0;
}