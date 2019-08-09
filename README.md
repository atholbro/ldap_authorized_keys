# ldap_authorized_keys
OpenSSH AuthorizedKeysCommand for looking up authorized_keys from LDAP.

Reads LDAP info from /etc/nslcd.conf, which should be setup if you're using nss-pam-ldapd (https://arthurdejong.org/nss-pam-ldapd/). In most cases, no LDAP configuration should be required for this utility if LDAP password authentication is already working.

## Building
```
$ mkdir build
$ cd build
$ cmake ../
$ make
```

## Installing
```
$ sudo chown root:root ldap_authorized_keys
$ sudo chmod 4755 ldap_authorized_keys
$ sudo mv ldap_authorized_keys /usr/local/bin
```
Note that setuid bit is required as your /etc/nslcd.conf should only be accessible by root. ldap_authorized_keys will drop root privileges after reading the configuration file. If nslcd.conf defines "uid", then that user will be used, otherwise ldap_authorized_keys will default to "nobody". Currently the "gid" from nslcd.conf is not used, the primary gid of the target user is used instead.

## Configure sshd
Edit your sshd_config at /etc/ssh/sshd_config using your favorite editor:
```
$ sudo $EDITOR /etc/ssh/sshd_config

AuthorizedKeysCommand /usr/local/bin/ldap_authorized_keys
AuthorizedKeysCommandUser nobody
```
If you'd like to restrict authorized keys to only LDAP then **after checking that LDAP keys are working**, comment out *AuthorizedKeysFile* in /etc/ssh/sshd_config.

Finally restart sshd (sudo systemctl restart sshd) for the changes to take effect.

### Why
There are a few other projects which also provide authorized_keys via LDAP, however everyone I found required additional dependencies like python, perl or lua. A shell script should be avoided since setuid is likely disabled for shell scripts and your LDAP config should only be readable by root.

The advantages of ldap_authorized_keys are:
* Written in C, and the only dependency is libldap.
* Reads nslcd.conf, no need to redefine LDAP configuration.
* Supports setuid and dropping root, so that your LDAP configuration can remain secure.
* Clear LDAP code should serve as a good example for anyone else wanting to use libldap (existing examples are rare and docs forget to mention depercated function alternatives).
