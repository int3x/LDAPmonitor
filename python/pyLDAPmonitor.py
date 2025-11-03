#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : pyLDAPmonitor.py
# Author             : Podalirius (@podalirius_)
# Date created       : 3 Jan 2022


import argparse
import os
import sys
import random
import ldap3
from impacket.examples.utils import init_ldap_session, parse_identity
from impacket.examples import logger
from ldap3.protocol.formatters.formatters import format_sid
import logging
import time
import datetime
import re
from itertools import chain


### Data utils

def dict_get_paths(d):
    paths = []
    for key in d.keys():
        if type(d[key]) == dict:
            paths = [[key] + p for p in dict_get_paths(d[key])]
        else:
            paths.append([key])
    return paths


def dict_path_access(d, path):
    for key in path:
        if key in d.keys():
            d = d[key]
        else:
            return None
    return d


### LDAPConsole

class LDAPConsole(object):
    def __init__(self, ldap_server, ldap_session, target_dn, logger, page_size=1000):
        super(LDAPConsole, self).__init__()
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session
        self.delegate_from = None
        self.target_dn = target_dn
        self.logger = logger
        self.page_size = page_size
        self.__results = {}
        self.all_ldap_attributes = []
        logging.debug("Using dn: %s" % self.target_dn)
        self.get_all_ldap_attributes()

    def get_all_ldap_attributes(self):
        baseDn = "CN=Schema," + self.ldap_server.info.other["configurationNamingContext"][0]
        # Clear all attributes
        self.all_ldap_attributes = []
        # Get all attributes from the schema
        results = self.query(query="(systemFlags:1.2.840.113556.1.4.803:=4)", baseDn=baseDn, attributes=["lDAPDisplayName"])
        for dn, entry in results.items():
            self.all_ldap_attributes.append(entry["lDAPDisplayName"])
        # Add all attributes
        self.all_ldap_attributes.append(ldap3.ALL_ATTRIBUTES)
        # Remove duplicates
        self.all_ldap_attributes = list(chain.from_iterable(self.all_ldap_attributes))
        self.all_ldap_attributes = sorted(list(set(self.all_ldap_attributes)))
        return self.all_ldap_attributes

    def query(self, query, attributes=['*'], baseDn=None, notify=False):
        # controls
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c5e87db-4728-4f29-b164-01dd7d7391ea
        LDAP_PAGED_RESULT_OID_STRING = "1.2.840.113556.1.4.319"
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f14f3610-ee22-4d07-8a24-1bf1466cba5f
        LDAP_SERVER_NOTIFICATION_OID = "1.2.840.113556.1.4.528"
        results = {}
        try:
            # https://ldap3.readthedocs.io/en/latest/searches.html#the-search-operation
            paged_response = True
            paged_cookie = None
            while paged_response == True:
                if baseDn is not None:
                    self.ldap_session.search(
                        baseDn,
                        query,
                        attributes=attributes,
                        size_limit=0,
                        paged_size=self.page_size,
                        paged_cookie=paged_cookie
                    )
                else:
                    self.ldap_session.search(
                        self.target_dn,
                        query,
                        attributes=attributes,
                        size_limit=0,
                        paged_size=self.page_size,
                        paged_cookie=paged_cookie
                    )
                #
                if "controls" in self.ldap_session.result.keys():
                    if LDAP_PAGED_RESULT_OID_STRING in self.ldap_session.result["controls"].keys():
                        next_cookie = self.ldap_session.result["controls"][LDAP_PAGED_RESULT_OID_STRING]["value"]["cookie"]
                        if len(next_cookie) == 0:
                            paged_response = False
                        else:
                            paged_response = True
                            paged_cookie = next_cookie
                    else:
                        paged_response = False
                else:
                    paged_response = False
                #
                for entry in self.ldap_session.response:
                    if entry['type'] != 'searchResEntry':
                        continue
                    results[entry['dn']] = entry["attributes"]
        except ldap3.core.exceptions.LDAPInvalidFilterError as e:
            print("Invalid Filter. (ldap3.core.exceptions.LDAPInvalidFilterError)")
        except Exception as e:
            raise e
        return results



def diff(last1_query_results, last2_query_results, logger, ignore_user_logon=False):
    ignored_keys = ["dnsRecord", "replUpToDateVector", "repsFrom"]
    if ignore_user_logon:
        ignored_keys.append("lastlogon")
        ignored_keys.append("logoncount")
    dateprompt = "\x1b[0m[\x1b[96m%s\x1b[0m]" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    common_keys = []
    for key in last2_query_results.keys():
        if key in last1_query_results.keys():
            common_keys.append(key)
        else:
            logging.info("%s \x1b[91m'%s' was deleted.\x1b[0m" % (dateprompt, key))
    for key in last1_query_results.keys():
        if key not in last2_query_results.keys() and key not in ignored_keys:
            logging.info("%s \x1b[92m'%s' was added.\x1b[0m" % (dateprompt, key))
    #
    for _dn in common_keys:
        paths_l2 = dict_get_paths(last2_query_results[_dn])
        paths_l1 = dict_get_paths(last1_query_results[_dn])
        #
        attrs_diff = []
        for p in paths_l1:
            if p[-1].lower() not in ignored_keys:
                value_before = dict_path_access(last2_query_results[_dn], p)
                value_after = dict_path_access(last1_query_results[_dn], p)
                if value_after != value_before:
                    attrs_diff.append((p, value_after, value_before))
        #
        if len(attrs_diff) != 0:
            # Print DN
            logging.info("%s \x1b[94m%s\x1b[0m" % (dateprompt, _dn))
            for _ad in attrs_diff:
                path, value_after, value_before = _ad
                attribute_path = "─>".join(["\"\x1b[93m%s\x1b[0m\"" % attr for attr in path])
                if any([ik in path for ik in ignored_keys]):
                    continue
                if type(value_before) == list:
                    value_before = [
                        v.strftime("%Y-%m-%d %H:%M:%S")
                        if isinstance(v, datetime.datetime)
                        else v
                        for v in value_before
                    ]
                if type(value_after) == list:
                    value_after = [
                        v.strftime("%Y-%m-%d %H:%M:%S")
                        if isinstance(v, datetime.datetime)
                        else v
                        for v in value_after
                    ]
                if value_after is not None and value_before is not None:
                    logging.info(" | Attribute %s changed from '\x1b[96m%s\x1b[0m' to '\x1b[96m%s\x1b[0m'" % (attribute_path, value_before, value_after))
                elif value_after is None and value_before is not None:
                    logging.info(" | Attribute %s = '\x1b[96m%s\x1b[0m' was deleted." % (attribute_path, value_before))
                elif value_after is not None and value_before is None:
                    logging.info(" | Attribute %s = '\x1b[96m%s\x1b[0m' was created." % (attribute_path, value_after))


def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Monitor LDAP changes live!')
    parser.add_argument('identity', action='store', help='domain.local/username[:password]')
    parser.add_argument('-use-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument("-debug", dest="debug", action="store_true", default=False, help="Debug mode.")
    parser.add_argument("-s", "--page-size", dest="page_size", type=int, default=1000, help="Page size.")
    parser.add_argument("-S", "--search-base", dest="search_base", type=str, default=None, help="Search base.")
    parser.add_argument("-r", "--randomize-delay", dest="randomize_delay", action="store_true", default=False, help="Randomize delay between two queries, between 1 and 5 seconds.")
    parser.add_argument("-t", "--time-delay", dest="time_delay", type=int, default=1, help="Delay between two queries in seconds (default: 1).")
    parser.add_argument("--ignore-user-logon", dest="ignore_user_logon", action="store_true", default=False, help="Ignores user logon events.")
    # parser.add_argument("-n", "--notify", dest="notify", action="store_true", default=False, help="Uses LDAP_SERVER_NOTIFICATION_OID to get only changed objects. (useful for large domains).")

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')
    group.add_argument('-dc-host', action='store', metavar="hostname", help='Hostname of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, -dc-ip will be used')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def query_all_naming_contexts(ldap_server, ldap_session, logger, page_size, search_base=None):
    results = {}
    if search_base is not None:
        naming_contexts = [search_base]
    else:
        naming_contexts = ldap_server.info.naming_contexts
    for nc in naming_contexts:
        lc = LDAPConsole(ldap_server, ldap_session, nc, logger=logger, page_size=page_size)
        _r = lc.query("(objectClass=*)", attributes=['*'])
        for key in _r.keys():
            if key not in results:
                results[key] = _r[key]
            else:
                print("[debug] key already exists: %s (this shouldn't be possible)" % key)
    return results


if __name__ == '__main__':
    args = parse_args()
    logger.init(args.ts, args.debug)
    logging.info("======================================================")
    logging.info("    LDAP live monitor v1.3        @podalirius_        ")
    logging.info("======================================================")

    domain, username, password, lmhash, nthash, args.k = parse_identity(args.identity, args.hashes, args.no_pass, args.aesKey, args.k)

    try:
        logging.debug("Trying to connect to %s ..." % args.dc_ip)
        ldap_server, ldap_session = init_ldap_session(
            domain,
            username,
            password,
            lmhash,
            nthash,
            args.k,
            args.dc_ip,
            args.dc_host,
            args.aesKey,
            use_ldaps=args.use_ldaps
        )

        logging.debug("Authentication successful!")

        last2_query_results = query_all_naming_contexts(ldap_server, ldap_session, logger, args.page_size, args.search_base)
        last1_query_results = last2_query_results

        logging.info("Listening for LDAP changes ...")
        running = True
        while running:
            if args.randomize_delay == True:
                delay = random.randint(1000, 5000) / 1000
            else:
                delay = args.time_delay
            logging.debug("Waiting %s seconds" % str(delay))
            time.sleep(delay)
            #
            last2_query_results = last1_query_results
            last1_query_results = query_all_naming_contexts(ldap_server, ldap_session, logger, args.page_size)
            #
            diff(last1_query_results, last2_query_results, logger=logger, ignore_user_logon=args.ignore_user_logon)

    except Exception as e:
        raise e
