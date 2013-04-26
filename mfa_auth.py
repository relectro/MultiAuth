#!/usr/bin/env python
__author__ = 'rbryce@mozilla.com'
#License: Mozilla Public License Version 2.0
#http://www.mozilla.org/MPL/2.0/index.txt

include yubikey
import ldap

"""
Get users otp from the command line.
query ldap for the users "key_id" and "api_key"
verify the otp. Exit allowing ssh to preceed
"""

USER = os.environ['USER']
LDAPHOST = '' # <% scope.lookup(::ldaphosts) %>
authserver_prefix='http://api.yubico.com/wsapi/verify?id='


def get_otpass():
    #No otp strings in the history
    otpass = raw_input("Press your Yubikey Now")

def yklookup():
    import ldap

## first you must open a connection to the server
    try:
	    l = ldap.open(LDAPHOST)
	    l.protocol_version = ldap.VERSION3
    except ldap.LDAPError, e:
	    print e
	# handle error however you like


## The next lines will also need to be changed to support your search requirements and directory
baseDN = "ou=users, ou=sysadmins, o=domain.com"
searchScope = ldap.SCOPE_SUBTREE
##Todo
## Retrieve just the objectclass that holds the keys
retrieveAttributes = None
searchFilter = "cn=USER"

try:
	ldap_result_id = l.search(baseDN, searchScope, searchFilter, retrieveAttributes)
	result_set = []
	while 1:
		result_type, result_data = l.result(ldap_result_id, 0)
		if (result_data == []):
			break
		else:
			if result_type == ldap.RES_SEARCH_ENTRY:
				default_api_id = result_data[0]
                default_api_key =result_data[1]
				result_set.append(result_data)
	#print result_set
except ldap.LDAPError, e:
	print e


def verify_yubikey():
    verify_paranoid(otp=otpass, api_id=default_api_id, authserver_prefix=authserver_prefix, api_key=default_api_key)
    #maybe set a temp file with attempts.  Clean exit clears temp file

def verify_gauth():
    verify_paranoid(otp=otpass, api_id=default_api_id, authserver_prefix=authserver_prefix, api_key=default_api_key)
