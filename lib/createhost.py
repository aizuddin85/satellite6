#!/usr/bin/python
import ldap
import ldap.sasl
import socket
import subprocess
import sys
import os
import hashlib
import json
import requests

SAT_URL = "https://satellite6.example.com"
SAT_API = "%s/katello/api/v2/" % SAT_URL
KATELLO_API = "%s/katello/api/" % SAT_URL
HOST_API = "%s/api/v2/hosts/" % SAT_URL
POST_HEADERS = {'content-type': 'application/json'}
SATUSER = "satadmin"
SATPASS = "satpass"
SSL_VERIFY = False
ORG_NAME = "T-Systems"
LDAP_URL = "ldap://ldap.example.com:389"
KINIT_PATH = "/usr/bin/kinit -k"
SVCA = "host/%s@EXAMPLE.COM" % socket.gethostname()
KEYTAB_FILE = "/etc/krb5.keytab"
PRIVI_HOST = raw_input("Enter hostname for provisioning: ")
ACCESS_PASS = raw_input("Enter access password for above host: ")


def json_get(location):
    r = requests.get(location, auth=(SATUSER, SATPASS), verify=SSL_VERIFY)
    return r.json()

def json_post(location, json_data):
    result = requests.post(
           location,
           data=json_data,
           auth=(SATUSER, SATPASS),
           verify=SSL_VERIFY,
           headers=POST_HEADERS)
    return result.json()

def host_check_exist(api_uri, name):
    check_host = json_get(api_uri + "?search=%s" % name)
    print check_host
    if len(check_host['results']) != 0:
         return True

def host_create_new(api_uri, name, env_id, ip_addr, mac_addr, arch_id, dom_id, loc_name, dom_name, build_status, hostgrp_id, org_name, sub_name, lang_value, keyboard_value, timezone_value, disk_value, managedby_value, access_value):
    host_new_id =  json_post(
    api_uri,json.dumps(
    {
        "name" : name,
        "environment_id" : env_id,
        "ip" : ip_addr,
        "mac" : mac_addr,
        "architecture_id" : arch_id,
        "domain_id" : dom_id,
        "location_name": loc_name,
        "interfaces.domain": dom_name,
        "build": build_status,
        "hostgroup_id" : hostgrp_id,
        "organization_name": org_name,
        "subnet_name": sub_name,
        "host_parameters_attributes" : [{"name": "lang_set", "value": lang_value}, {"name": "keyboard_set", "value": keyboard_value},
         {"name": "timezone_set", "value": timezone_value}, {"name": "disk_set", "value": disk_value}, {"name": "managedby", "value": managedby_value}, {"name": "access_pass", "value": access_value}]}
    ))
    print host_new_id


def check_path(path):
    if os.path.exists(path) is False:
        return False



def check_installhash(installpass, adinstallhash):
     hash = hashlib.md5()
     hash.update(installpass)
     if hash.hexdigest() not in adinstallhash:
         return False
     else:
         return True

if check_path(KEYTAB_FILE) is False:
    print "Error: No Keytab file found!"
    sys.exit(1)


KINIT_ARGS = KINIT_PATH + " " + SVCA
kinit = subprocess.call(str(KINIT_ARGS), shell=True)
if kinit != 0:
    print "Error, unable to initialize kerberos ticket!"
    sys.exit(1)


attrs = ["LNXManagedBy", \
"LNXIPAddress", \
"LNXLanguage", \
"LNXKeyboard", \
"LNXTimezone", \
"LNXHardware", \
"LNXComputerInstallHash"]



ldapcon = ldap.initialize(LDAP_URL,trace_level=0)
ldapcon.protocol_version = 3
auth_tokens = ldap.sasl.gssapi()
ldapcon.sasl_interactive_bind_s('', auth_tokens)
ldap_result = ldapcon.search_s("OU=Software by Network,OU=Computer Directory,DC=example,DC=com", ldap.SCOPE_SUBTREE, "(cn=%s)" % PRIVI_HOST, attrs)


# If the shellLNXComputerType sets to Server during compadd.
if len(ldap_result) == 0:
    ldap_result = ldapcon.search_s("OU=Server Directory,DC=example,DC=com", ldap.SCOPE_SUBTREE, "(cn=%s)" % PRIVI_HOST, attrs)


for attr,key in ldap_result:
   if 'LNXLanguage' in key:
       for lang in key.get('LNXLanguage'):
           lang_val = lang
   else:
       print "Error: Missing LNXLanguage in AD!"
       sys.exit(1)

   if 'LNXKeyboard' in key:
       for keyboard in key.get('LNXKeyboard'):
           keyboard_val = keyboard
   else:
       print "Error Missing LNXKeyboard in AD!"
       sys.exit(1)

   if 'LNXTimezone' in key:
       for tzone in key.get('LNXTimezone'):
           timezone_val = tzone
   else:
       print "Error: Missing LNXTimezone in AD!"
       sys.exit(1)

   if 'LNXHardware' in key:
       for hdisk in key.get('LNXHardware'):
           disk_val = hdisk
   else:
       print "Error: Missing LNXHardware in AD!"
       sys.exit(1)

   if 'LNXComputerInstallHash' in key:
       for kickhash in key.get('LNXComputerInstallHash'):
           access_val = kickhash
   else:
       print "Error: Missing LNXComputerInstallHash in AD!"
       sys.exit(1)

   if 'LNXIPAddress' in key:
       for ip in key.get('LNXIPAddress'):
           ipaddress = ip
   else:
        print "Erorr: Missing LNXIPAddress in AD!"
        sys.exit(1)
   if 'LNXManagedBy' in key:
       for manage in key.get('LNXManagedBy'):
           managedby = manage
   else:
        print "Error: Missing LNXManagedBy in AD!"
        sys.exit(1)


if check_installhash(ACCESS_PASS, access_val) is False:
    print "Error: Install hash has failed verification!"
    sys.exit(1)
else:
    pass


if host_check_exist(HOST_API, PRIVI_HOST) is True:
    print "Error: Host exists!"
    sys.exit(1)
else:
    print lang_val
    print keyboard_val
    host_create_new(HOST_API, PRIVI_HOST, "1", ipaddress, "ff:ff:ff:ff:ff:aa","1" ,"1" , "Global Linux", "example.com", "True", 1, "Example Organization", "Cyberjaya Subnet", lang_val, keyboard_val, timezone_val, disk_val, managedby, ACCESS_PASS)

