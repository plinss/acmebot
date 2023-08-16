#!/usr/bin/env python3

# Certificate manager using ACME protocol
#
# To install on Debian:
# apt-get install build-essential libssl-dev libffi-dev python3-dev python3-pip
# pip3 install acmebot


import argparse
import base64
import binascii
import collections
import datetime
import enum
import getpass
import glob
import grp
import hashlib
import heapq
import json
import os
import pwd
import random
import re
import shlex
import shutil
import socket
import string
import struct
import subprocess
import sys
import tempfile
import time
import urllib


import DNS

import OpenSSL

from acme import client, messages

from asn1crypto import ocsp as asn1_ocsp
from asn1crypto import x509 as asn1_x509

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

import josepy

import pkg_resources

import yaml


DNSTuple = collections.namedtuple('DNSTuple', ['datetime', 'name_server', 'domain_name', 'identifier', 'response', 'attempt_count'])
ChallengeTuple = collections.namedtuple('ChallengeTuple', ['identifier', 'response'])
AuthorizationTuple = collections.namedtuple('AuthorizationTuple', ['datetime', 'domain_name', 'authorization_resource'])
KeyData = collections.namedtuple('KeyData', ['key', 'timestamp'])
SCTData = collections.namedtuple('SCTData', ['version', 'id', 'timestamp', 'extensions', 'signature'])
PrivateKeyData = collections.namedtuple('PrivateKeyData', ['name', 'key_options', 'keys', 'backup_keys', 'previous_keys',
                                                           'generated_key', 'rolled_key', 'changed_key', 'issued_certificates'])
KeyCipherData = collections.namedtuple('KeyCipherData', ['cipher', 'passphrase', 'forced'])
CertificateData = collections.namedtuple('CertificateData', ['certificate_name', 'key_type', 'certificate', 'chain', 'config'])
TLSAData = collections.namedtuple('TLSAData', ['host', 'port', 'usage', 'selector', 'protocol', 'ttl',
                                               'certificates', 'chain', 'private_keys'])

class ErrorCode(enum.IntEnum):
    NONE = 0
    GENERAL = 1
    FATAL = 2
    EXCEPTION = 3
    CONFIG = 4
    PERMISSION = 5
    DNS = 6
    HOOK = 7
    ACME = 8
    AUTH = 9
    KEY = 10
    PARAM = 11
    VERIFY = 12


class WarningCode(enum.IntEnum):
    NONE = 0
    GENERAL = 100
    CONFIG = 101
    KEY = 102
    DNS = 103
    AUTH = 104
    SERVICE = 105
    SCT = 106
    OCSP = 107


class AcmeError(Exception):
    pass


class PrivateKeyError(Exception):
    pass


class FileTransaction(object):
    __slots__ = ['file', 'temp_file_path', 'file_type', 'file_path', 'chmod', 'timestamp']
    tempdir = None

    def __init__(self, file_type, file_path, chmod=None, timestamp=None, mode='w'):
        self.file_type = file_type
        self.file_path = file_path
        self.chmod = chmod
        self.timestamp = timestamp
        temp_file_descriptor, self.temp_file_path = tempfile.mkstemp(dir=FileTransaction.tempdir)
        self.file = open(temp_file_descriptor, mode)

    def __del__(self):
        if (self.file):
            self.file.close()
            self.file = None

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if (self.file):
            self.file.close()

    def write(self, data):
        self.file.write(data)


class AcmeManager:

    def __init__(self):
        script_entry = sys.argv[0]
        self.script_dir = os.path.dirname(os.path.realpath(script_entry))
        self.script_name = os.path.basename(script_entry)
        self.script_version = pkg_resources.get_distribution('acmebot').version
        self.error_code = ErrorCode.NONE
        self.warning_code = WarningCode.NONE

        self._color_codes = {
            'black': 30,
            'red': 31,
            'green': 32,
            'yellow': 33,
            'blue': 34,
            'magenta': 35,
            'cyan': 36,
            'light gray': 37,
            'dark gray': 90,
            'light red': 91,
            'light green': 92,
            'light yellow': 93,
            'light blue': 94,
            'light magenta': 95,
            'light cyan': 96,
            'white': 97
        }
        self._style_codes = {
            'normal': 0,
            'bold': 1,
            'bright': 1,
            'dim': 2,
            'underline': 4,
            'underlined': 4,
            'blink': 5,
            'reverse': 7,
            'invert': 7,
            'hidden': 8
        }

        argparser = argparse.ArgumentParser(description='ACME Certificate Manager')
        argparser.add_argument('--version', action='version', version='%(prog)s ' + self.script_version)
        argparser.add_argument('private_key_names', nargs='*')
        argparser.add_argument('-q', '--quiet',
                               action='store_true', dest='quiet', default=False,
                               help="Don't print status messages to stdout or warnings to stderr")
        argparser.add_argument('-v', '--verbose',
                               action='store_true', dest='verbose', default=False,
                               help='Print more detailed status messages to stdout')
        argparser.add_argument('-d', '--debug',
                               action='store_true', dest='debug', default=False,
                               help='Print detailed debugging information to stdout')
        argparser.add_argument('-D', '--detail',
                               action='store_true', dest='detail', default=False,
                               help='Print more detailed debugging information to stdout')
        argparser.add_argument('--color',
                               action='store_true', dest='color', default=False,
                               help='Colorize output')
        argparser.add_argument('--no-color',
                               action='store_true', dest='no_color', default=False,
                               help='Suppress colorized output')
        argparser.add_argument('-c', '--config',
                               dest='config_path', default=self.script_name, metavar='CONFIG_PATH',
                               help='Specify file path for config')
        argparser.add_argument('-w', '--randomwait',
                               action='store_true', dest='random_wait', default=False,
                               help='Wait for a random time before executing')
        argparser.add_argument('-r', '--rollover',
                               action='store_true', dest='rollover', default=False,
                               help='Rollover private keys and Diffie-Hellman parameters')
        argparser.add_argument('-F', '--force',
                               action='store_true', dest='force_rollover', default=False,
                               help='Force rollover for keys within HPKP window')
        argparser.add_argument('-R', '--renew',
                               action='store_true', dest='renew', default=False,
                               help='Renew certificate regardless of age')
        argparser.add_argument('-K', '--revoke',
                               action='store_true', dest='revoke', default=False,
                               help='Revoke certificate')
        argparser.add_argument('-a', '--auth',
                               action='store_true', dest='auth', default=False,
                               help='Update authorizations only')
        argparser.add_argument('-C', '--certs',
                               action='store_true', dest='certs', default=False,
                               help='Update certificates only')
        argparser.add_argument('-t', '--tlsa',
                               action='store_true', dest='tlsa', default=False,
                               help='Update TLSA records only')
        argparser.add_argument('-s', '--sct',
                               action='store_true', dest='sct', default=False,
                               help='Update Signed Certificate Timestamps only')
        argparser.add_argument('-o', '--ocsp',
                               action='store_true', dest='ocsp', default=False,
                               help='Update OCSP responses only')
        argparser.add_argument('-V', '--verify',
                               action='store_true', dest='verify', default=False,
                               help='Verify certificate installation only')
        argparser.add_argument('--register',
                               action='store_true', dest='register', default=False,
                               help='Register client only')
        argparser.add_argument('--export-client',
                               action='store_true', dest='export_client', default=False,
                               help='Export client key')
        argparser.add_argument('--show-config',
                               action='store_true', dest='show_config', default=False,
                               help='Display configuration settings')
        argparser.add_argument('--quick',
                               action='store_true', dest='quick', default=False,
                               help='Avoid long running operations')
        argparser.add_argument('-A', '--accept',
                               action='store_true', dest='accept', default=False,
                               help='Automatically accept registration terms of service')
        argparser.add_argument('-p', '--pass', nargs=1, default=False,
                               action='store', dest='passphrase', metavar='PASSPHRASE',
                               help='Passphrase for private keys')
        self.args = argparser.parse_args()

        if (self.args.debug):
            sys.excepthook = debug_hook

        self.acme_client = None
        self.key_passphrases = {}
        self.updated_services = set()
        self.hooks = collections.OrderedDict()

        self.config = {'settings': {'color_output': True}}
        self.config, self.config_file_path = self._load_config(self.args.config_path, ('.', os.path.join('/etc', self.script_name), self.script_dir))
        self._failed_auth = set()
        self._key_types = ('rsa', 'ecdsa')
        self._config_defaults = {
            'settings': {
                'follower_mode': False,
                'log_level': 'debug',
                'color_output': True,
                'key_types': self._key_types,
                'key_size': 4096,
                'key_curve': 'secp384r1',
                'key_cipher': 'blowfish',
                'key_passphrase': None,
                'key_provided': False,
                'dhparam_size': 2048,
                'ecparam_curve': ['secp521r1', 'secp384r1', 'secp256k1'],
                'file_user': 'root',
                'file_group': 'ssl-cert',
                'log_user': 'root',
                'log_group': 'adm',
                'warning_exit_code': False,
                'hpkp_days': 60,
                'pin_subdomains': True,
                'hpkp_report_uri': None,
                'ocsp_must_staple': False,
                'ocsp_responder_urls': ['http://ocsp.int-x3.letsencrypt.org'],
                'ct_submit_logs': ['google_argon', 'google_xenon'],
                'renewal_days': 30,
                'expiration_days': 730,
                'auto_rollover': False,
                'max_dns_lookup_attempts': 30,
                'dns_lookup_delay': 10,
                'max_domains_per_order': 100,
                'max_authorization_attempts': 30,
                'authorization_delay': 10,
                'cert_poll_time': 30,
                'max_ocsp_verify_attempts': 10,
                'ocsp_verify_retry_delay': 5,
                'min_run_delay': 300,
                'max_run_delay': 3600,
                'acme_directory_url': 'https://acme-v02.api.letsencrypt.org/directory',
                'acme_directory_verify_ssl': True,
                'reload_zone_command': '/etc/bind/reload-zone.sh',
                'nsupdate_command': '/usr/bin/nsupdate',
                'public_suffix_list_url': 'https://publicsuffix.org/list/public_suffix_list.dat',
                'verify': None,
                'services': None
            },
            'directories': {
                'pid': '/var/run',
                'log': os.path.join('/var/log', self.script_name),
                'resource': os.path.join('/var/local', self.script_name),
                'private_key': '/etc/ssl/private',
                'backup_key': '/etc/ssl/private',
                'previous_key': None,
                'full_key': '/etc/ssl/private',
                'certificate': '/etc/ssl/certs',
                'full_certificate': '/etc/ssl/certs',
                'chain': '/etc/ssl/certs',
                'param': '/etc/ssl/params',
                'challenge': '/etc/ssl/challenges',
                'http_challenge': None,
                'hpkp': '/etc/ssl/hpkp',
                'ocsp': '/etc/ssl/ocsp/',
                'sct': '/etc/ssl/scts/{name}/{key_type}',
                'update_key': '/etc/ssl/update_keys',
                'archive': '/etc/ssl/archive',
                'temp': None
            },
            'key_type_suffixes': {
                'rsa': '.rsa',
                'ecdsa': '.ecdsa'
            },
            'file_names': {
                'log': self.script_name + '.log',
                'private_key': '{name}{suffix}.key',
                'backup_key': '{name}_backup{suffix}.key',
                'previous_key': '{name}_previous{suffix}.key',
                'full_key': '{name}_full{suffix}.key',
                'certificate': '{name}{suffix}.pem',
                'full_certificate': '{name}+root{suffix}.pem',
                'chain': '{name}_chain{suffix}.pem',
                'param': '{name}_param.pem',
                'challenge': '{name}',
                'hpkp': '{name}.{server}',
                'ocsp': '{name}{suffix}.ocsp',
                'sct': '{ct_log_name}.sct'
            },
            'hpkp_headers': {
                'apache': 'Header always set Public-Key-Pins "{header}"\n',
                'nginx': 'add_header Public-Key-Pins "{header}" always;\n'
            },
            'services': {
                'apache': 'systemctl reload-or-restart apache2',
                'coturn': 'systemctl reload-or-restart coturn',
                'dovecot': 'systemctl reload-or-restart dovecot',
                'etherpad': 'systemctl reload-or-restart etherpad',
                'mysql': 'systemctl reload-or-restart mysql',
                'nginx': 'systemctl reload-or-restart nginx',
                'postfix': 'systemctl reload-or-restart postfix',
                'postgresql': 'systemctl reload-or-restart postgresql',
                'prosody': 'systemctl reload-or-restart prosody',
                'slapd': 'systemctl reload-or-restart slapd',
                'synapse': 'systemctl reload-or-restart matrix-synapse',
                'znc': 'systemctl reload-or-restart znc'
            },
            'ct_logs': {
                'google_argon': [
                    {
                        'log_id': 'sh4FzIuizYogTodm+Su5iiUgZ2va+nDnsklTLe+LkF4=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6Tx2p1yKY4015NyIYvdrk36es0uAc1zA4PQ+TGRY+3ZjUTIYY9Wyu+3q/147JG4vNVKLtDWarZwVqGkg6lAYzA==',
                        'url': 'https://ct.googleapis.com/logs/argon2020/',
                        'start': '2020-01-01T00:00:00Z',
                        'end': '2021-01-01T00:00:00Z',
                    },
                    {
                        'log_id': '9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOM=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETeBmZOrzZKo4xYktx9gI2chEce3cw/tbr5xkoQlmhB18aKfsxD+MnILgGNl0FOm0eYGilFVi85wLRIOhK8lxKw==',
                        'url': 'https://ct.googleapis.com/logs/argon2021/',
                        'start': '2021-01-01T00:00:00Z',
                        'end': '2022-01-01T00:00:00Z',
                    },
                    {
                        'log_id': 'KXm+8J45OSHwVnOfY6V35b5XfZxgCvj5TV0mXCVdx4Q=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeIPc6fGmuBg6AJkv/z7NFckmHvf/OqmjchZJ6wm2qN200keRDg352dWpi7CHnSV51BpQYAj1CQY5JuRAwrrDwg==',
                        'url': 'https://ct.googleapis.com/logs/argon2022/',
                        'start': '2022-01-01T00:00:00Z',
                        'end': '2023-01-01T00:00:00Z',
                    },
                    {
                        'log_id': '6D7Q2j71BjUy51covIlryQPTy9ERa+zraeF3fW0GvW4=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0JCPZFJOQqyEti5M8j13ALN3CAVHqkVM4yyOcKWCu2yye5yYeqDpEXYoALIgtM3TmHtNlifmt+4iatGwLpF3eA==',
                        'url': 'https://ct.googleapis.com/logs/argon2023/',
                        'start': '2023-01-01T00:00:00Z',
                        'end': '2024-01-01T00:00:00Z',
                    },
                ],
                'google_xenon': [
                    {
                        'log_id': 'B7dcG+V9aP/xsMYdIxXHuuZXfFeUt2ruvGE6GmnTohw=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZU75VqjyzSTgFZKAnWg1QeYfFFIRZTMK7q3kWWZsmHhQdrBYnHRZ3OA4kUeUx0JN+xX+dSgt1ruqUhhl7jOvmw==',
                        'url': 'https://ct.googleapis.com/logs/xenon2020/',
                        'start': '2020-01-01T00:00:00Z',
                        'end': '2021-01-01T00:00:00Z',
                    },
                    {
                        'log_id': 'fT7y+I//iFVoJMLAyp5SiXkrxQ54CX8uapdomX4i8Nc=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAER+1MInu8Q39BwDZ5Rp9TwXhwm3ktvgJzpk/r7dDgGk7ZacMm3ljfcoIvP1E72T8jvyLT1bvdapylajZcTH6W5g==',
                        'url': 'https://ct.googleapis.com/logs/xenon2021/',
                        'start': '2021-01-01T00:00:00Z',
                        'end': '2022-01-01T00:00:00Z',
                    },
                    {
                        'log_id': 'RqVV63X6kSAwtaKJafTzfREsQXS+/Um4havy/HD+bUc=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+WS9FSxAYlCVEzg8xyGwOrmPonoV14nWjjETAIdZvLvukPzIWBMKv6tDNlQjpIHNrUcUt1igRPpqoKDXw2MeKw==',
                        'url': 'https://ct.googleapis.com/logs/xenon2022/',
                        'start': '2022-01-01T00:00:00Z',
                        'end': '2023-01-01T00:00:00Z',
                    },
                    {
                        'log_id': 'rfe++nz/EMiLnT2cHj4YarRnKV3PsQwkyoWGNOvcgoo=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEchY+C+/vzj5g3ZXLY3q5qY1Kb2zcYYCmRV4vg6yU84WI0KV00HuO/8XuQqLwLZPjwtCymeLhQunSxgAnaXSuzg==',
                        'url': 'https://ct.googleapis.com/logs/xenon2023/',
                        'start': '2023-01-01T00:00:00Z',
                        'end': '2024-01-01T00:00:00Z',
                    },
                ],
                'cloudflare_numbus': [
                    {
                        'log_id': 'Xqdz+d9WwOe1Nkh90EngMnqRmgyEoRIShBh1loFxRVg=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE01EAhx4o0zPQrXTcYjgCt4MVFsT0Pwjzb1RwrM0lhWDlxAYPP6/gyMCXNkOn/7KFsjL7rwk78tHMpY8rXn8AYg==',
                        'url': 'https://ct.cloudflare.com/logs/nimbus2020/',
                        'start': '2020-01-01T00:00:00Z',
                        'end': '2021-01-01T00:00:00Z',
                    },
                    {
                        'log_id': 'RJRlLrDuzq/EQAfYqP4owNrmgr7YyzG1P9MzlrW2gag=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExpon7ipsqehIeU1bmpog9TFo4Pk8+9oN8OYHl1Q2JGVXnkVFnuuvPgSo2Ep+6vLffNLcmEbxOucz03sFiematg==',
                        'url': 'https://ct.cloudflare.com/logs/nimbus2021/',
                        'start': '2021-01-01T00:00:00Z',
                        'end': '2022-01-01T00:00:00Z',
                    },
                    {
                        'log_id': 'QcjKsd8iRkoQxqE6CUKHXk4xixsD6+tLx2jwkGKWBvY=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESLJHTlAycmJKDQxIv60pZG8g33lSYxYpCi5gteI6HLevWbFVCdtZx+m9b+0LrwWWl/87mkNN6xE0M4rnrIPA/w==',
                        'url': 'https://ct.cloudflare.com/logs/nimbus2022/',
                        'start': '2022-01-01T00:00:00Z',
                        'end': '2023-01-01T00:00:00Z',
                    },
                    {
                        'log_id': 'ejKMVNi3LbYg6jjgUh7phBZwMhOFTTvSK8E6V6NS61I=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi/8tkhjLRp0SXrlZdTzNkTd6HqmcmXiDJz3fAdWLgOhjmv4mohvRhwXul9bgW0ODgRwC9UGAgH/vpGHPvIS1qA==',
                        'url': 'https://ct.cloudflare.com/logs/nimbus2023/',
                        'start': '2023-01-01T00:00:00Z',
                        'end': '2024-01-01T00:00:00Z',
                    },
                ],
                'digicert_log_server': {
                    'log_id': 'VhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0=',
                    'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAkbFvhu7gkAW6MHSrBlpE1n4+HCFRkC5OLAjgqhkTH+/uzSfSl8ois8ZxAD2NgaTZe1M9akhYlrYkes4JECs6A==',
                    'url': 'https://ct1.digicert-ct.com/log/',
                },
                'digicert_log_server_2': {
                    'log_id': 'h3W/51l8+IxDmV+9827/Vo1HVjb/SrVgwbTq/16ggw8=',
                    'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzF05L2a4TH/BLgOhNKPoioYCrkoRxvcmajeb8Dj4XQmNY+gxa4Zmz3mzJTwe33i0qMVp+rfwgnliQ/bM/oFmhA==',
                    'url': 'https://ct2.digicert-ct.com/log/',
                },
                'digicert_yeti': [
                    {
                        'log_id': '8JWkWfIA0YJAEC0vk4iOrUv+HUfjmeHQNKawqKqOsnM=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEURAG+Zo0ac3n37ifZKUhBFEV6jfcCzGIRz3tsq8Ca9BP/5XUHy6ZiqsPaAEbVM0uI3Tm9U24RVBHR9JxDElPmg==',
                        'url': 'https://yeti2020.ct.digicert.com/log/',
                        'start': '2020-01-01T00:00:00Z',
                        'end': '2021-01-01T00:00:00Z',
                    },
                    {
                        'log_id': 'XNxDkv7mq0VEsV6a1FbmEDf71fpH3KFzlLJe5vbHDso=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6J4EbcpIAl1+AkSRsbhoY5oRTj3VoFfaf1DlQkfi7Rbe/HcjfVtrwN8jaC+tQDGjF+dqvKhWJAQ6Q6ev6q9Mew==',
                        'url': 'https://yeti2021.ct.digicert.com/log/',
                        'start': '2021-01-01T00:00:00Z',
                        'end': '2022-01-01T00:00:00Z',
                    },
                    {
                        'log_id': 'IkVFB1lVJFaWP6Ev8fdthuAjJmOtwEt/XcaDXG7iDwI=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEn/jYHd77W1G1+131td5mEbCdX/1v/KiYW5hPLcOROvv+xA8Nw2BDjB7y+RGyutD2vKXStp/5XIeiffzUfdYTJg==',
                        'url': 'https://yeti2022.ct.digicert.com/log/',
                        'start': '2022-01-01T00:00:00Z',
                        'end': '2023-01-01T00:00:00Z',
                    },
                    {
                        'log_id': 'Nc8ZG7+xbFe/D61MbULLu7YnICZR6j/hKu+oA8M71kw=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfQ0DsdWYitzwFTvG3F4Nbj8Nv5XIVYzQpkyWsU4nuSYlmcwrAp6m092fsdXEw6w1BAeHlzaqrSgNfyvZaJ9y0Q==',
                        'url': 'https://yeti2023.ct.digicert.com/log/',
                        'start': '2023-01-01T00:00:00Z',
                        'end': '2024-01-01T00:00:00Z',
                    },
                ],
                'digicert_nessie': [
                    {
                        'log_id': 'xlKg7EjOs/yrFwmSxDqHQTMJ6ABlomJSQBujNioXxWU=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4hHIyMVIrR9oShgbQMYEk8WX1lmkfFKB448Gn93KbsZnnwljDHY6MQqEnWfKGgMOq0gh3QK48c5ZB3UKSIFZ4g==',
                        'url': 'https://nessie2020.ct.digicert.com/log/',
                        'start': '2020-01-01T00:00:00Z',
                        'end': '2021-01-01T00:00:00Z',
                    },
                    {
                        'log_id': '7sCV7o1yZA+S48O5G8cSo2lqCXtLahoUOOZHssvtxfk=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9o7AiwrbGBIX6Lnc47I6OfLMdZnRzKoP5u072nBi6vpIOEooktTi1gNwlRPzGC2ySGfuc1xLDeaA/wSFGgpYFg==',
                        'url': 'https://nessie2021.ct.digicert.com/log/',
                        'start': '2021-01-01T00:00:00Z',
                        'end': '2022-01-01T00:00:00Z',
                    },
                    {
                        'log_id': 'UaOw9f0BeZxWbbg3eI8MpHrMGyfL956IQpoN/tSLBeU=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJyTdaAMoy/5jvg4RR019F2ihEV1McclBKMe2okuX7MCv/C87v+nxsfz1Af+p+0lADGMkmNd5LqZVqxbGvlHYcQ==',
                        'url': 'https://nessie2022.ct.digicert.com/log/',
                        'start': '2022-01-01T00:00:00Z',
                        'end': '2023-01-01T00:00:00Z',
                    },
                    {
                        'log_id': 's3N3B+GEUPhjhtYFqdwRCUp5LbFnDAuH3PADDnk2pZo=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEXu8iQwSCRSf2CbITGpUpBtFVt8+I0IU0d1C36Lfe1+fbwdaI0Z5FktfM2fBoI1bXBd18k2ggKGYGgdZBgLKTg==',
                        'url': 'https://nessie2023.ct.digicert.com/log/',
                        'start': '2023-01-01T00:00:00Z',
                        'end': '2024-01-01T00:00:00Z',
                    },
                ],
                'sectigo_sabre': {
                    'log_id': 'VYHUwhaQNgFK6gubVzxT8MDkOHhwJQgXL6OqHQcT0ww=',
                    'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8m/SiQ8/xfiHHqtls9m7FyOMBg4JVZY9CgiixXGz0akvKD6DEL8S0ERmFe9U4ZiA0M4kbT5nmuk3I85Sk4bagA==',
                    'url': 'https://sabre.ct.comodo.com/',
                },
                'sectigo_mammoth': {
                    'log_id': 'b1N2rDHwMRnYmQCkURX/dxUcEdkCwQApBo2yCJo32RM=',
                    'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7+R9dC4VFbbpuyOL+yy14ceAmEf7QGlo/EmtYU6DRzwat43f/3swtLr/L8ugFOOt1YU/RFmMjGCL17ixv66MZw==',
                    'url': 'https://mammoth.ct.comodo.com/',
                },
                'lets_encrypt_oak': [
                    {
                        'log_id': '5xLysDd+GmL7jskMYYTx6ns3y1YdESZb8+DzS/JBVG4=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfzb42Zdr/h7hgqgDCo1vrNJqGqbcUvJGJEER9DDqp19W/wFSB0l166hD+U5cAXchpH8ZkBNUuvOHS0OnJ4oJrQ==',
                        'url': 'https://oak.ct.letsencrypt.org/2020/',
                        'start': '2020-01-01T00:00:00Z',
                        'end': '2021-01-07T00:00:00Z',
                    },
                    {
                        'log_id': 'lCC8Ho7VjWyIcx+CiyIsDdHaTV5sT5Q9YdtOL1hNosI=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELsYzGMNwo8rBIlaklBIdmD2Ofn6HkfrjK0Ukz1uOIUC6Lm0jTITCXhoIdjs7JkyXnwuwYiJYiH7sE1YeKu8k9w==',
                        'url': 'https://oak.ct.letsencrypt.org/2021/',
                        'start': '2021-01-01T00:00:00Z',
                        'end': '2022-01-07T00:00:00Z',
                    },
                    {
                        'log_id': '36Veq2iCTx9sre64X04+WurNohKkal6OOxLAIERcKnM=',
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhjyxDVIjWt5u9sB/o2S8rcGJ2pdZTGA8+IpXhI/tvKBjElGE5r3de4yAfeOPhqTqqc+o7vPgXnDgu/a9/B+RLg==',
                        'url': 'https://oak.ct.letsencrypt.org/2022/',
                        'start': '2022-01-01T00:00:00Z',
                        'end': '2023-01-07T00:00:00Z',
                    },

                    {
                        'log_id': self._hex_to_base64('B7:3E:FB:24:DF:9C:4D:BA:75:F2:39:C5:BA:58:F4:6C:5D:FC:42:CF:7A:9F:35:C4:9E:1D:09:81:25:ED:B4:99'),
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsz0OeL7jrVxEXJu+o4QWQYLKyokXHiPOOKVUL3/TNFFquVzDSer7kZ3gijxzBp98ZTgRgMSaWgCmZ8OD74mFUQ==',
                        'url': 'https://oak.ct.letsencrypt.org/2023/',
                        'start': '2023-01-01T00:00Z',
                        'end': '2024-01-07T00:00Z',
                    },
                    {
                        'log_id': self._hex_to_base64('3B:53:77:75:3E:2D:B9:80:4E:8B:30:5B:06:FE:40:3B:67:D8:4F:C3:F4:C7:BD:00:0D:2D:72:6F:E1:FA:D4:17'),
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVkPXfnvUcre6qVG9NpO36bWSD+pet0Wjkv3JpTyArBog7yUvuOEg96g6LgeN5uuk4n0kY59Gv5RzUo2Wrqkm/Q==',
                        'url': 'https://oak.ct.letsencrypt.org/2024h1/',
                        'start': '2023-12-20T00:00Z',
                        'end': '2024-07-20T00:00Z',
                    },
                    {
                        'log_id': self._hex_to_base64('3F:17:4B:4F:D7:22:47:58:94:1D:65:1C:84:BE:0D:12:ED:90:37:7F:1F:85:6A:EB:C1:BF:28:85:EC:F8:64:6E'),
                        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE13PWU0fp88nVfBbC1o9wZfryUTapE4Av7fmU01qL6E8zz8PTidRfWmaJuiAfccvKu5+f81wtHqOBWa+Ss20waA==',
                        'url': 'https://oak.ct.letsencrypt.org/2024h2/',
                        'start': '2024-06-20T00:00Z',
                        'end': '2025-01-20T00:00Z',
                    },
                ],
            }
        }

    @property
    def exit_code(self) -> int:
        if (ErrorCode.NONE != self.error_code):
            return self.error_code.value
        if ((WarningCode.NONE != self.warning_code) and self._setting('warning_exit_code')):
            return self.warning_code.value
        return 0

    def _hex_to_base64(self, hex: str) -> str:
        return base64.b64encode(binascii.unhexlify(hex.replace(':', ''))).decode('ascii')

    def _load_yaml(self, stream, object_pairs_hook=dict):
        class OrderedLoader(yaml.SafeLoader):
            pass

        def construct_mapping(loader, node):
            loader.flatten_mapping(node)
            return object_pairs_hook(loader.construct_pairs(node))

        OrderedLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)
        return yaml.load(stream, OrderedLoader)

    def _load_config_file(self, config_file_path):
        _, extension = os.path.splitext(config_file_path)
        try:
            self._detail('Reading config from ', config_file_path, '\n')
            with open(config_file_path) as config_file:
                if ('.json' == extension):
                    return json.load(config_file, object_pairs_hook=collections.OrderedDict)
                return self._load_yaml(config_file, object_pairs_hook=collections.OrderedDict)
        except Exception as error:
            self._fatal('Error reading config file ', config_file_path, ': ', error, '\n', code=ErrorCode.CONFIG)

    def _find_configs(self, config_file_path):
        config_dir = os.path.dirname(config_file_path)
        file_paths = []
        for extension in ('.json', '.yaml', '.yml'):
            file_paths += glob.glob(os.path.join(config_dir, 'conf.d', '*' + extension))
        return file_paths

    def _merge_dicts(self, base, extra):
        if (not isinstance(base, dict)):
            base = collections.OrderedDict()
        for key, value in extra.items():
            if (isinstance(value, dict)):
                base[key] = self._merge_dicts(base.get(key), value)
            else:
                base[key] = value
        return base

    def _load_config(self, file_path, search_paths=[]):
        file_path = os.path.expanduser(file_path)
        search_paths = [''] if (os.path.isabs(file_path)) else search_paths
        file_path, file_extension = os.path.splitext(file_path)
        extensions = ('.json', '.yaml', '.yml') if not file_extension else [file_extension]
        for search_path in search_paths:
            for extension in extensions:
                config_file_path = os.path.join(search_path, file_path) + extension
                if (os.path.isfile(config_file_path)):
                    config = self._load_config_file(config_file_path)
                    for file_path in sorted(self._find_configs(config_file_path)):
                        config = self._merge_dicts(config, self._load_config_file(file_path))
                    return (config, config_file_path)
        self._fatal('Config file ', file_path, file_extension, ' not found\n', code=ErrorCode.CONFIG)

    def _message(self, *args):
        message = ''
        for arg in args:
            message += str(arg, 'utf-8', 'replace') if isinstance(arg, bytes) else str(arg)
        return message

    def _indent(self, *args):
        return '\n'.join([('    ' + line) for line in self._message(*args).split('\n')])

    def _colorize(self, stream, color, style, message):
        if (stream.isatty() and (self.args.color or self._setting('color_output')) and (not self.args.no_color)):
            stream.write('\033[{style};{color}m{message}\033[0m'.format(color=self._color_codes[color], style=self._style_codes[style], message=message))
        else:
            stream.write(message)

    def _status(self, *args):
        if (not self.args.quiet):
            sys.stdout.write(self._message(*args))
        if (self._setting('log_level') in ['normal', 'verbose', 'debug', 'detail']):
            self._log(*args)

    def _info(self, *args, color='yellow', style='normal'):
        if ((self.args.verbose or self.args.debug or self.args.detail) and not self.args.quiet):
            self._colorize(sys.stdout, color, style, self._message(*args))
        if (self._setting('log_level') in ['verbose', 'debug', 'detail']):
            self._log(*args)

    def _debug(self, *args, color='dark gray', style='normal'):
        if ((self.args.debug or self.args.detail) and not self.args.quiet):
            self._colorize(sys.stdout, color, style, self._message(*args))
        if (self._setting('log_level') in ['debug', 'detail']):
            self._log(*args)

    def _detail(self, *args, color='light gray', style='normal'):
        if (self.args.detail and not self.args.quiet):
            self._colorize(sys.stdout, color, style, self._message(*args))
        if (self._setting('log_level') == 'detail'):
            self._log(*args)

    def _warn(self, *args, code: WarningCode = None, color='red', style='normal'):
        self.warning_code = code if (code is not None) else WarningCode.GENERAL
        if (not self.args.quiet):
            self._colorize(sys.stderr, color, style, self._message(*args))
        if (self._setting('log_level') in ['normal', 'debug', 'verbose']):
            self._log(*args)

    def _error(self, *args, code: ErrorCode = None, color='red', style='bold'):
        self.error_code = code if (code is not None) else ErrorCode.GENERAL
        message = self._message(*args)
        self._colorize(sys.stderr, color, style, message)
        self._log(message)

    def _fatal(self, *args, code: ErrorCode = None, color='red', style='bold'):
        self.error_code = code if (code is not None) else ErrorCode.FATAL
        message = self._message(*args)
        self._colorize(sys.stderr, color, style, message)
        self._log(message)
        raise AcmeError(message)

    def _log(self, *args):
        if (hasattr(self, 'config') and self._directory('log') and self._file_name('log') and self._setting('log_level')):
            log_file_path = self._file_path('log', self.script_name)
            try:
                with self._open_file(log_file_path, mode='a+', chmod=0o640, warn=False,
                                     user=self._setting('log_user'), group=self._setting('log_group')) as log_file:
                    log_file.write(self._message(*args))
            except Exception:
                sys.stderr.write('Unable to write to log file ' + log_file_path + '\n')

    def _makedir(self, dir_path, *, chmod=None, warn=True, user=None, group=None):
        if (not os.path.isdir(dir_path)):
            try:
                os.makedirs(dir_path)
                if (chmod):
                    if (chmod & 0o700):
                        chmod |= 0o100
                    if (chmod & 0o070):
                        chmod |= 0o010
                    if (chmod & 0o007):
                        chmod |= 0o001
                    try:
                        os.chmod(dir_path, chmod)
                    except PermissionError as error:
                        if (warn):
                            self._error('Unable to set directory mode for ', dir_path, '\n', self._indent(error), '\n', code=ErrorCode.PERMISSION)
                    try:
                        os.chown(dir_path, self._get_user_id(user or self._setting('file_user')), self._get_group_id(group or self._setting('file_group')))
                    except PermissionError as error:
                        if (warn):
                            self._error('Unable to set directory ownership for ', dir_path, ' to ',
                                        self._setting('file_user'), ':', self._setting('file_group'), '\n', self._indent(error), '\n',
                                        code=ErrorCode.PERMISSION)
            except Exception as error:
                if (warn):
                    self._error('Unable to create directory ', dir_path, '\n', self._indent(error), '\n', code=ErrorCode.PERMISSION)

    def _open_file(self, file_path, *, mode='r', chmod=0o666, warn=True, user=None, group=None):
        def opener(file_path, flags):
            file = os.open(file_path, flags, mode=chmod)
            if (user or group):
                os.chown(file_path, self._get_user_id(user or self._setting('file_user')), self._get_group_id(group or self._setting('file_group')))
            return file
        if ((('w' in mode) or ('a' in mode)) and isinstance(file_path, str)):
            self._makedir(os.path.dirname(file_path), chmod=chmod, warn=warn, user=user, group=group)
        return open(file_path, mode, opener=opener)

    def _archive_file(self, file_type, file_path, archive_name='', archive_date=datetime.datetime.now()):
        if (os.path.isfile(file_path) and (not os.path.islink(file_path)) and (archive_name is not None)):
            archive_file_path = os.path.join(self._directory('archive'),
                                             archive_name,
                                             archive_date.strftime('%Y_%m_%d_%H%M%S') if (archive_date) else '',
                                             file_type + '.' + os.path.basename(file_path))
            self._makedir(os.path.dirname(archive_file_path), chmod=0o640)
            shutil.move(file_path, archive_file_path)
            self._detail('Archived ', file_path, ' as ', archive_file_path, '\n')
            return (file_path, archive_file_path)
        return (None, None)

    def _get_user_id(self, user_name):
        try:
            return pwd.getpwnam(user_name).pw_uid
        except Exception:
            return -1

    def _get_group_id(self, group_name):
        try:
            return grp.getgrnam(group_name).gr_gid
        except Exception:
            return -1

    def _rename_file(self, old_file_path, new_file_path, *, chmod=None, timestamp=None, user=None, group=None):
        if (os.path.isfile(old_file_path)):
            self._makedir(os.path.dirname(new_file_path), chmod=chmod)
            shutil.move(old_file_path, new_file_path)
            if (chmod):
                try:
                    os.chmod(new_file_path, chmod)
                except PermissionError as error:
                    self._error('Unable to set file mode for ', new_file_path, '\n', self._indent(error), '\n', code=ErrorCode.PERMISSION)
            if (timestamp):
                try:
                    os.utime(new_file_path, (timestamp, timestamp))
                except PermissionError as error:
                    self._error('Unable to set file time for ', new_file_path, '\n', self._indent(error), '\n', code=ErrorCode.PERMISSION)
            try:
                os.chown(new_file_path, self._get_user_id(user or self._setting('file_user')), self._get_group_id(group or self._setting('file_group')))
            except PermissionError as error:
                self._error('Unable to set file ownership for ', new_file_path, ' to ',
                            self._setting('file_user'), ':', self._setting('file_group'), '\n', self._indent(error), '\n', code=ErrorCode.PERMISSION)
            return new_file_path
        return None

    def _commit_file_transactions(self, file_transactions, archive_name=''):
        archived_files = []
        committed_files = []
        try:
            if (archive_name is not None):
                archive_date = datetime.datetime.now()
                for file_transaction in file_transactions:
                    archived_files.append(self._archive_file(file_transaction.file_type, file_transaction.file_path,
                                                             archive_name=archive_name, archive_date=archive_date))
            for file_transaction in file_transactions:
                committed_files.append(self._rename_file(file_transaction.temp_file_path, file_transaction.file_path,
                                                         chmod=file_transaction.chmod, timestamp=file_transaction.timestamp))
        except Exception as error:  # restore any archived files
            for committed_file_path in committed_files:
                if (committed_file_path):
                    os.remove(committed_file_path)
            for original_file_path, archived_file_path in archived_files:
                if (original_file_path):
                    shutil.move(archived_file_path, original_file_path)
            raise error

    def _get_list(self, config, key, default=[]):
        value = config.get(key, default)
        return value if (isinstance(value, collections.abc.Iterable) and not isinstance(value, str)) else [] if (value is None) else [value]

    def _config(self, section_name, key=None, default=None):
        return self.config.get(section_name, {}).get(key, default) if (key) else self.config.get(section_name, {})

    def _account(self, key):
        return self._config('account', key)

    def _setting(self, key):
        return self._config('settings', key)

    def _setting_list(self, key):
        return self._get_list(self.config.get('settings', {}), key)

    def _setting_int(self, key):
        try:
            return int(self._setting(key))
        except Exception:
            return 0

    def _directory(self, file_type):
        directory = self._config('directories', file_type, '')
        return os.path.normpath(os.path.join(os.path.dirname(self.config_file_path), directory)) if (directory) else directory

    def _key_type_suffix(self, key_type):
        return self._config('key_type_suffixes', key_type, '')

    def _file_name(self, file_type):
        return self._config('file_names', file_type, '')

    def _file_path(self, file_type, file_name, key_type=None, **kwargs):
        if (self._directory(file_type) is not None):
            directory = self._directory(file_type).format(name=file_name, key_type=key_type, suffix=self._key_type_suffix(key_type), **kwargs)
            file_name = self._file_name(file_type).format(name=file_name, key_type=key_type, suffix=self._key_type_suffix(key_type), **kwargs)
            return os.path.join(directory, file_name.replace('*', '_'))
        return ''

    def _service(self, service_name):
        return self._config('services', service_name)

    def _http_challenge_directory(self, domain_name, zone_name):
        if (domain_name in self.config.get('http_challenges', {})):
            return self._config('http_challenges', domain_name)
        http_challenge_directory = self._directory('http_challenge')
        if (http_challenge_directory):
            host_name = domain_name[0:-len(zone_name)].strip('.') or '.'
            return http_challenge_directory.format(fqdn=domain_name, zone=zone_name, host=host_name)

    def _zone_key(self, zone_name):
        key_data = self._config('zone_update_keys', zone_name)
        if (key_data):
            if (isinstance(key_data, str)):
                return {'file': os.path.join(self._directory('update_key'), key_data)}
            if ('file' in key_data):
                key_data = key_data.copy()
                key_data['file'] = os.path.join(self._directory('update_key'), key_data['file'])
                return key_data
        return None

    def _option(self, config, key):
        return config.get(key, self._setting(key))

    def _option_list(self, config, key):
        value = config.get(key, self._setting(key))
        return value if (isinstance(value, collections.abc.Iterable) and not isinstance(value, str)) else [] if (value is None) else [value]

    def _option_int(self, config, key):
        try:
            return int(self._option(config, key))
        except Exception:
            return 0

    def _datetime_from_asn1_generaltime(self, general_time):
        try:
            return datetime.datetime.strptime(general_time.decode('ascii'), '%Y%m%d%H%M%SZ')
        except ValueError:
            return datetime.datetime.strptime(general_time.decode('ascii'), '%Y%m%d%H%M%S%z')

    def _get_challenge(self, authorization_resource, type):
        for challenge in authorization_resource.body.challenges:
            if (type == challenge.typ):
                return challenge
        return None

    def _get_domain_names(self, zone_dict, zone_name):
        domain_names = []
        for host_name in self._get_list(zone_dict, zone_name):
            host_name = host_name.strip().lower()
            domain_names.append(zone_name if ('@' == host_name) else (host_name + '.' + zone_name))
        return domain_names

    def _random_string(self, length):
        return ''.join([random.choice(string.ascii_lowercase) for _ in range(0, length)])

    def _reload_zone(self, zone_name, critical=True):
        if (not self._setting('reload_zone_command')):
            if (critical):
                self._fatal('reload_zone_command not configured and needed for local DNS updates, ',
                            'either configure local DNS updates or switch to http authorizations\n', code=ErrorCode.CONFIG)
            return
        try:
            subprocess.check_output([self._setting('reload_zone_command'), zone_name], stderr=subprocess.STDOUT)
            self._debug('Reloading zone ', zone_name, '\n')
            time.sleep(2)
        except subprocess.CalledProcessError as error:
            if (critical):
                self._fatal('Failed to reload zone ', zone_name, ', code: ', error.returncode, '\n', self._indent(error.output), '\n', code=ErrorCode.DNS)
            else:
                self._warn('Failed to reload zone ', zone_name, ', code: ', error.returncode, '\n', self._indent(error.output), '\n', code=WarningCode.DNS)
        except Exception as error:
            if (critical):
                self._fatal('Failed to reload zone ', zone_name, '\n', self._indent(error), '\n', code=ErrorCode.DNS)
            else:
                self._warn('Failed to reload zone ', zone_name, '\n', self._indent(error), '\n', code=WarningCode.DNS)

    def _dns_request(self, name, type, name_server=None):
        attempt_count = 9
        request = DNS.Request(server=name_server) if (name_server) else DNS.Request()
        while (True):
            try:
                response = request.req(name=name, qtype=type, protocol='tcp')
                if ('SERVFAIL' == response.header['status']):
                    raise Exception('Server failure')
                if ('NOERROR' == response.header['status']):
                    return (response, None)
                return (None, response.header['status'])
            except Exception as error:
                attempt_count -= 1
                if (0 < attempt_count):
                    self._detail(f'DNS Error: {error}; retries {attempt_count}', '\n')
                    time.sleep(5)
                else:
                    self._error(f'DNS Error: {error}; requesting {type}, record for {name}', ((f' @{name_server}') if (name_server) else ''), '\n',
                                code=ErrorCode.DNS)
                    break
        return (None, None)

    def _get_primary_name_server(self, zone_name):
        response, status = self._dns_request(zone_name, 'SOA')
        if (response):
            return response.answers[0]['data'][0]
        self._warn('Unable to find primary name server for ', zone_name, ' ', status, '\n', code=WarningCode.DNS)
        return None

    def _get_name_servers(self, zone_name):
        response, status = self._dns_request(zone_name, 'NS')
        if (response):
            return [answer['data'] for answer in response.answers]
        self._warn('Unable to find name servers for ', zone_name, ' ', status, '\n', code=WarningCode.DNS)
        return []

    def _lookup_dns_challenge(self, name_server, domain_name):
        response, _ = self._dns_request('_acme-challenge.' + domain_name, 'TXT', name_server)
        if (response):
            return [answer['data'][0].decode('ascii') for answer in response.answers]
        return []

    def _lookup_tlsa_records(self, host, port, protocol, name_server=None):
        response, _ = self._dns_request('_{port}._{protocol}.{host}'.format(port=port, protocol=protocol, host=host), 52, name_server)
        if (response):
            return ['{} {} {} {}'.format(answer['data'][0], answer['data'][1], answer['data'][2], binascii.hexlify(answer['data'][3:]).decode('ascii'))
                    for answer in response.answers if (52 == answer['type'])]
        return []

    def _update_zone(self, updates, zone_name, zone_key, operation):
        server = 'server {server} {port}\n'.format(server=zone_key['server'], port=zone_key.get('port', '')) if ('server' in zone_key) else ''
        update_commands = '{server}zone {zone}\n{update}\nsend\n'.format(server=server, zone=zone_name, update='\n'.join(updates))
        try:
            self._detail('nsupdate:\n', update_commands)
            subprocess.check_output([self._setting('nsupdate_command'), '-v', '-k', zone_key['file']],
                                    input=update_commands.encode('ascii'), stderr=subprocess.STDOUT)
            self._debug(operation, ' records for ', zone_name, '\n')
            return True
        except subprocess.CalledProcessError as error:
            self._warn(operation, ' records failed for ', zone_name, ', code: ', error.returncode, '\n', self._indent(error.output), '\n',
                       code=WarningCode.DNS)
        except Exception as error:
            self._warn(operation, ' records failed for ', zone_name, '\n', self._indent(error), '\n', code=WarningCode.DNS)
        return False

    def _set_dns_challenges(self, zone_name, zone_key, challenges):
        updates = ['update add _acme-challenge.{host} 300 TXT "{response}"'.format(host=challenges[domain_name].identifier,
                                                                                   response=challenges[domain_name].response)
                   for domain_name in challenges]
        return self._update_zone(updates, zone_name, zone_key, 'Set DNS challenges')

    def _remove_dns_challenges(self, zone_name, zone_key, challenges):
        updates = ['update delete _acme-challenge.{host} 300 TXT "{response}"'.format(host=challenges[domain_name].identifier,
                                                                                      response=challenges[domain_name].response)
                   for domain_name in challenges]
        self._update_zone(updates, zone_name, zone_key, 'Remove DNS challenges')

    def _tlsa_data(self, records, certificates=None, chain=[], private_keys=None):
        data = []
        for record in records:
            if (isinstance(record, str)):
                record = {'host': record}
            data.append(TLSAData(record.get('host', '@'), record.get('port', 443),
                                 record.get('usage', 'pkix-ee'), record.get('selector', 'spki'),
                                 record.get('protocol', 'tcp'), record.get('ttl', 300),
                                 certificates, chain, private_keys))
        return data

    def _set_tlsa_records(self, zone_name, zone_key, tlsa_records):
        usage = {'pkix-ta': '0', 'pkix-ee': '1', 'dane-ta': '2', 'dane-ee': '3'}
        updates = []
        name_server = self._get_primary_name_server(zone_name)
        if (not name_server):
            return
        for tlsa_data in tlsa_records:
            host_name = zone_name if ('@' == tlsa_data.host) else (tlsa_data.host + '.' + zone_name)
            if (tlsa_data.usage in usage):
                usage_id = usage[tlsa_data.usage]
            else:
                self._error('Unknown TLSA usage ', tlsa_data.usage, '\n', code=ErrorCode.CONFIG)
                usage_id = usage['pkix-ee']
            if ('cert' == tlsa_data.selector):
                if (tlsa_data.usage in ('pkix-ee', 'dane-ee')):
                    certificates = [self._certificate_bytes(certificate) for certificate in tlsa_data.certificates]
                else:
                    certificates = [self._certificate_bytes(certificate) for certificate in tlsa_data.chain]
                keys = []
            else:
                certificates = []
                if (tlsa_data.usage in ('pkix-ee', 'dane-ee')):
                    keys = [self._public_key_bytes(private_key) for private_key in tlsa_data.private_keys]
                else:
                    keys = [self._certificate_public_key_bytes(certificate) for certificate in tlsa_data.chain]

            record_name = '_{port}._{protocol}.{host}.'.format(host=host_name, port=tlsa_data.port, protocol=tlsa_data.protocol)
            records = []
            record_bytes = set()
            for certificate_bytes in certificates:
                if (certificate_bytes and certificate_bytes not in record_bytes):   # dedupe chain certificates (may be shared between key types)
                    record_bytes.add(certificate_bytes)
                    records.append('{usage} 0 1 {digest}'.format(usage=usage_id, digest=hashlib.sha256(certificate_bytes).hexdigest()))
                    records.append('{usage} 0 2 {digest}'.format(usage=usage_id, digest=hashlib.sha512(certificate_bytes).hexdigest()))
            for key_bytes in keys:
                if (key_bytes and key_bytes not in record_bytes):   # dedupe chain certificates (may be shared between key types)
                    record_bytes.add(key_bytes)
                    records.append('{usage} 1 1 {digest}'.format(usage=usage_id, digest=hashlib.sha256(key_bytes).hexdigest()))
                    records.append('{usage} 1 2 {digest}'.format(usage=usage_id, digest=hashlib.sha512(key_bytes).hexdigest()))

            if (set(records) == set(self._lookup_tlsa_records(host_name, tlsa_data.port, tlsa_data.protocol, name_server))):
                self._detail('TLSA records already present for ', record_name, '\n')
                continue

            updates.append('update delete {record_name} {ttl} TLSA'.format(record_name=record_name, ttl=tlsa_data.ttl))
            for record in records:
                updates.append('update add {record_name} {ttl} TLSA {record}'.format(record_name=record_name, record=record, ttl=tlsa_data.ttl))
        if (updates):
            self._update_zone(updates, zone_name, zone_key, 'Set TLSA')

    def _remove_tlsa_records(self, zone_name, zone_key, tlsa_records):
        updates = []
        for tlsa_data in tlsa_records:
            host_name = zone_name if ('@' == tlsa_data.host) else (tlsa_data.host + '.' + zone_name)
            updates.append('update delete _{port}._{proto}.{host}. TLSA'.format(port=tlsa_data.port, proto=tlsa_data.protocol, host=host_name))
        self._update_zone(updates, zone_name, zone_key, 'Remove TLSA')

    def update_services(self, services):
        self.updated_services.update(services)

    def reload_services(self):
        reloaded = False
        for service_name in self.updated_services:
            service_command = self._service(service_name)
            if (service_command):
                self._debug('Reloading service ', service_name, '\n')
                try:
                    output = subprocess.check_output(service_command, shell=True, stderr=subprocess.STDOUT)
                    reloaded = True
                    if (output):
                        self._warn('Service ', service_name, ' responded to reload with:\n', output, '\n', code=WarningCode.SERVICE)
                except subprocess.CalledProcessError as error:
                    self._warn('Service ', service_name, ' reload failed, code: ', error.returncode, '\n', self._indent(error.output), '\n',
                               code=WarningCode.SERVICE)
            else:
                self._error('Service ', service_name, ' does not have registered reload command\n', code=ErrorCode.CONFIG)
        return reloaded

    def generate_rsa_key(self, key_size):
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, key_size)
        return key

    def generate_ecdsa_key(self, key_curve):
        key_curve = key_curve.lower()
        if ('secp256r1' == key_curve):
            key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        elif ('secp384r1' == key_curve):
            key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        elif ('secp521r1' == key_curve):
            key = ec.generate_private_key(ec.SECP521R1(), default_backend())
        else:
            self._error('Unsupported key curve: ', key_curve, '\n', code=ErrorCode.CONFIG)
            return None
#        return OpenSSL.crypto.PKey.from_cryptography_key(key)  # currently not supported
        key_pem = key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL, encryption_algorithm=NoEncryption())
        return OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_pem)

    def generate_private_key(self, key_type, options):
        if ('rsa' == key_type):
            return self.generate_rsa_key(*options)
        if ('ecdsa' == key_type):
            return self.generate_ecdsa_key(*options)
        self._error('Unknown key type ', key_type.upper(), '\n', code=ErrorCode.CONFIG)
        return None

    def key_cipher_data(self, private_key_name, force_prompt=False):
        if (private_key_name in self.key_passphrases):
            if (self.key_passphrases[private_key_name] or (not force_prompt)):
                return self.key_passphrases[private_key_name]
        private_keys = self._config('private_keys')
        if (private_key_name in private_keys):
            passphrase = self._option(private_keys[private_key_name], 'key_passphrase')
            if ((passphrase is True) or (force_prompt and not passphrase)):
                if (self.args.passphrase):
                    passphrase = self.args.passphrase[0]
                else:
                    passphrase = os.getenv('{script}_PASSPHRASE'.format(script=self.script_name.upper()))
                    if (not passphrase):
                        if (sys.stdin.isatty()):
                            passphrase = getpass.getpass('Enter private key password for {name}: '.format(name=private_key_name))
                        else:
                            passphrase = sys.stdin.readline().strip()
            key_cipher_data = KeyCipherData(self._option(private_keys[private_key_name], 'key_cipher'), passphrase, force_prompt) if (passphrase) else None
            self.key_passphrases[private_key_name] = key_cipher_data
            return key_cipher_data
        return None

    def load_private_key(self, file_type, file_name, key_type, key_cipher_data=None):
        key_file_path = self._file_path(file_type, file_name, key_type)
        if (os.path.isfile(key_file_path)):
            try:
                with open(key_file_path, 'r') as private_key_file:
                    key_pem = private_key_file.read()
                    if ('-----BEGIN ENCRYPTED PRIVATE KEY-----' in key_pem):
                        if (not key_cipher_data):
                            key_cipher_data = self.key_cipher_data(file_name, force_prompt=True)
                        private_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_pem.encode('ascii'),
                                                                     key_cipher_data.passphrase.encode('utf-8'))
                    else:
                        private_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_pem.encode('ascii'))
                    return KeyData(private_key, os.stat(key_file_path).st_mtime)
            except Exception:
                raise PrivateKeyError(key_file_path)
        return KeyData(None, None)

    def save_private_key(self, file_type, file_name, key_type, private_key, key_cipher_data,
                         timestamp=None, certificate=None, chain=[], dhparam_pem=None, ecparam_pem=None, chmod=0o640):
        with FileTransaction(file_type, self._file_path(file_type, file_name, key_type), chmod=chmod, timestamp=timestamp) as transaction:
            if (private_key):
                if (key_cipher_data and not key_cipher_data.forced):
                    try:
                        key_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key, key_cipher_data.cipher,
                                                                 key_cipher_data.passphrase.encode('utf-8'))
                    except Exception:
                        raise PrivateKeyError(file_name)
                else:
                    key_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key)
                transaction.write(key_pem.decode('ascii'))
                if (certificate):
                    transaction.write('\n')
                    self._save_certificate(transaction, certificate, chain=chain, dhparam_pem=dhparam_pem, ecparam_pem=ecparam_pem)
        return transaction

    def archive_private_key(self, file_type, file_name, key_type, archive_name='', archive_date=None):
        self._archive_file(file_type, self._file_path(file_type, file_name, key_type), archive_name=archive_name, archive_date=archive_date)

    def _need_to_rollover(self, backup_key_age, expiration_days):
        if ((backup_key_age is not None) and expiration_days):
            return (expiration_days <= backup_key_age.days)
        return False

    def _safe_to_rollover(self, backup_key_age, hpkp_days):
        if ((backup_key_age is not None) and hpkp_days):
            return (hpkp_days < backup_key_age.days)
        return True

    def _private_key_matches_options(self, key_type, private_key, options):
        if ('rsa' == key_type):
            return (private_key.bits() == options[0])
        if ('ecdsa' == key_type):
            return (private_key.to_cryptography_key().curve.name == options[0])
        self._error('Unknown key type ', key_type.upper(), '\n', code=ErrorCode.CONFIG)
        return False

    def _private_key_descripton(self, key_type, options):
        if ('rsa' == key_type):
            return '{key_size} bits'.format(key_size=options[0])
        if ('ecdsa' == key_type):
            return 'curve {key_curve}'.format(key_curve=options[0])
        self._error('Unknown key type ', key_type.upper(), '\n', code=ErrorCode.PERMISSION)
        return ''

    def _public_key_bytes(self, private_key):
        if (private_key):
            return private_key.to_cryptography_key().public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return None

    def _certificate_public_key_bytes(self, certificate):
        if (certificate):
            return certificate.get_pubkey().to_cryptography_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return None

    def _public_key_digest(self, private_key, digest='sha256'):
        if ('sha256' == digest):
            return hashlib.sha256(self._public_key_bytes(private_key)).digest()
        return hashlib.sha512(self._public_key_bytes(private_key)).digest()

    def _certificate_bytes(self, certificate):
        if (certificate):
            return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, certificate)
        return None

    def _generate_hpkp_headers(self, file_name, private_keys, hpkp_days, pin_subdomains, report_uri):
        pins = '; '.join([r'pin-sha256=\"{digest}\"'.format(digest=base64.b64encode(self._public_key_digest(private_key)).decode('ascii'))
                         for private_key in private_keys])
        duration = str(hpkp_days * 86400)
        sub_domains = ' includeSubdomains;' if (pin_subdomains) else ''
        report = r' report-uri=\"{report_uri}\";'.format(report_uri=report_uri) if (report_uri) else ''
        header = '{pins}; max-age={duration};{sub_domains}{report}'.format(pins=pins, duration=duration, sub_domains=sub_domains, report=report)

        hpkp_headers = self._config('hpkp_headers')
        server_headers = {}
        for server, header_format in hpkp_headers.items():
            if (header_format):
                server_headers[server] = header_format.format(header=header, server=server, name=file_name)
        return server_headers

    def hpkp_headers_present(self, file_name, private_keys, hpkp_days, pin_subdomains, report_uri):
        server_headers = self._generate_hpkp_headers(file_name, private_keys, hpkp_days, pin_subdomains, report_uri)
        for server, header in server_headers.items():
            header_file_path = self._file_path('hpkp', file_name, server=server)
            if (os.path.isfile(header_file_path)):
                with open(header_file_path, 'r') as header_file:
                    if (header != header_file.read()):
                        return False
            else:
                return False
        return True

    def save_hpkp_headers(self, file_name, private_keys, hpkp_days, pin_subdomains, report_uri):
        server_headers = self._generate_hpkp_headers(file_name, private_keys, hpkp_days, pin_subdomains, report_uri)
        transactions = []
        for server, header in server_headers.items():
            with FileTransaction('hpkp', self._file_path('hpkp', file_name, server=server), chmod=0o644) as transaction:
                transaction.write(header)
                transactions.append(transaction)
            self._add_hook('hpkp_header_installed', key_name=file_name, server=server, header=header,
                           hpkp_file=self._file_path('hpkp', file_name, server=server))
        return transactions

    def archive_hpkp_headers(self, file_name, archive_name='', archive_date=None):
        hpkp_headers = self._config('hpkp_headers')
        for server in hpkp_headers:
            self._archive_file('hpkp', self._file_path('hpkp', file_name, server=server), archive_name=archive_name, archive_date=archive_date)

    def _ocsp_must_staple_extension(self):
        return OpenSSL.crypto.X509Extension(
            b'1.3.6.1.5.5.7.1.24',
            critical=False,
            value=b'DER:30:03:02:01:05')

    def get_alt_names(self, certificate):
        for index in range(certificate.get_extension_count()):
            extension = certificate.get_extension(index)
            if (b'subjectAltName' == extension.get_short_name()):
                return [alt_name.split(':')[1] for alt_name in str(extension).split(', ')]
        return []

    def has_oscp_must_staple(self, certificate):
        ocsp_must_staple = self._ocsp_must_staple_extension()
        for index in range(certificate.get_extension_count()):
            extension = certificate.get_extension(index)
            if ((ocsp_must_staple.get_short_name() == extension.get_short_name())
                    and (ocsp_must_staple.get_data() == extension.get_data())):
                return True
        return False

    def _private_key_matches_certificate(self, private_key, certificate):
        return self._public_key_bytes(private_key) == self._certificate_public_key_bytes(certificate)

    def _certificate_digest(self, certificate, digest='sha256'):
        return certificate.digest(digest).decode('ascii').replace(':', '').lower()

    def _certificates_match(self, certificate1, certificate2):
        return (OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate1) ==
                OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate2))

    def load_certificate(self, file_type, file_name, key_type):
        try:
            with open(self._file_path(file_type, file_name, key_type), 'r') as certificate_file:
                return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate_file.read().encode('ascii'))
        except Exception:
            return None

    def load_root_certificates(self):
        root_certificates = collections.OrderedDict()
        for key_type in self._key_types:
            root_certificates[key_type] = self.load_certificate('certificate', os.path.join(os.path.dirname(self.config_file_path), 'root_cert'), key_type)
        return root_certificates

    def save_certificate(self, file_type, file_name, key_type, certificate, chain=[], root_certificate=None, dhparam_pem=None, ecparam_pem=None):
        with FileTransaction(file_type, self._file_path(file_type, file_name, key_type), chmod=0o644) as transaction:
            self._save_certificate(transaction.file, certificate, chain=chain, root_certificate=root_certificate,
                                   dhparam_pem=dhparam_pem, ecparam_pem=ecparam_pem)
        return transaction

    def archive_certificate(self, file_type, file_name, key_type, archive_name='', archive_date=None):
        self._archive_file(file_type, self._file_path(file_type, file_name, key_type), archive_name=archive_name, archive_date=archive_date)

    def _save_certificate(self, certificate_file, certificate, chain=None, root_certificate=None, dhparam_pem=None, ecparam_pem=None):
        certificate_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate).decode('ascii')
        certificate_not_before = self._datetime_from_asn1_generaltime(certificate.get_notBefore())
        certificate_file.write(certificate.get_subject().commonName + ' issued at ' + certificate_not_before.strftime('%Y-%m-%d %H:%M:%S UTC') + '\n')
        certificate_file.write(certificate_pem)
        if (chain):
            self._save_chain(certificate_file, chain, '\n')
        if (root_certificate):
            root_certificate_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, root_certificate).decode('ascii')
            certificate_file.write('\n' + root_certificate.get_subject().commonName + '\n')
            certificate_file.write(root_certificate_pem)
        if (dhparam_pem):
            certificate_file.write('\n' + dhparam_pem)
        if (ecparam_pem):
            certificate_file.write('\n' + ecparam_pem)

    def load_chain(self, file_name, key_type):
        chain = []
        try:
            pem_data = None
            if (self._directory('chain')):
                chain_file_path = self._file_path('chain', file_name, key_type)
                if (os.path.isfile(chain_file_path)):
                    with open(chain_file_path) as chain_file:
                        pem_data = chain_file.read()
                        index = 0
            if (not pem_data):
                with open(self._file_path('certificate', file_name, key_type)) as certificate_file:
                    pem_data = certificate_file.read()
                    index = 1
            certificate_pems = re.findall('-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', pem_data, re.DOTALL)[index:]
            for certificate_pem in certificate_pems:
                chain.append(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate_pem.encode('ascii')))
        except Exception:
            pass
        return chain

    def decode_full_chain(self, full_chain_pem):
        full_chain = []
        certificate_pems = re.findall('-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', full_chain_pem, re.DOTALL)
        for certificate_pem in certificate_pems:
            full_chain.append(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate_pem.encode('ascii')))
        return full_chain[0], full_chain[1:]

    def save_chain(self, file_name, key_type, chain):
        with FileTransaction('chain', self._file_path('chain', file_name, key_type), chmod=0o644) as transaction:
            self._save_chain(transaction.file, chain)
        return transaction

    def archive_chain(self, file_name, key_type, archive_name='', archive_date=None):
        self._archive_file('chain', self._file_path('chain', file_name, key_type), archive_name=archive_name, archive_date=archive_date)

    def _save_chain(self, chain_file, chain, lead_in=''):
        for chain_certificate in chain:
            chain_certificate_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, chain_certificate).decode('ascii')
            chain_file.write(lead_in + chain_certificate.get_subject().commonName + '\n')
            chain_file.write(chain_certificate_pem)
            lead_in = '\n'

    def generate_dhparam(self, dhparam_size):
        if (dhparam_size):
            try:
                return subprocess.check_output(['openssl', 'dhparam', str(dhparam_size)], stderr=subprocess.DEVNULL).decode('ascii')
            except Exception:
                pass
        return None

    def generate_ecparam(self, ecparam_curves):
        ecparam_pem = ''
        for ecparam_curve in ecparam_curves:
            try:
                ecparam_pem += subprocess.check_output(['openssl', 'ecparam', '-name', ecparam_curve], stderr=subprocess.DEVNULL).decode('ascii')
            except Exception:
                pass
        return ecparam_pem if ecparam_pem else None

    def params_present(self, file_name, dhparam_pem, ecparam_pem):
        param_file_path = self._file_path('param', file_name)
        if (os.path.isfile(param_file_path)):
            with open(param_file_path, 'r') as param_file:
                params = param_file.read()
                return (((not dhparam_pem) or (dhparam_pem in params)) and ((not ecparam_pem) or (ecparam_pem in params)))
        return False

    def check_dhparam(self, dhparam_pem):
        if (dhparam_pem):
            try:
                openssl = subprocess.Popen(['openssl', 'dhparam', '-check'], stdin=subprocess.PIPE,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                openssl.communicate(input=dhparam_pem.encode('ascii'))
                return (0 == openssl.returncode)
            except Exception as error:
                self._fatal('Unable to run openssl dhparam -check\n', error, '\n', code=ErrorCode.PARAM)
        return False

    def check_ecparam(self, ecparam_pem):
        if (ecparam_pem):
            try:
                openssl = subprocess.Popen(['openssl', 'ecparam', '-check'], stdin=subprocess.PIPE,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                openssl.communicate(input=ecparam_pem.encode('ascii'))
                return (0 == openssl.returncode)
            except Exception as error:
                self._fatal('Unable to run openssl ecparam -check\n', error, '\n', code=ErrorCode.PARAM)
        return False

    def dhparam_size(self, dhparam_pem):
        if (dhparam_pem):
            try:
                output = subprocess.check_output(['openssl', 'dhparam', '-text'], input=dhparam_pem.encode('ascii'), stderr=subprocess.DEVNULL)
                match = re.search(r'DH Parameters: \(([0-9]+) bit\)', output.decode('ascii'))
                if (match):
                    return int(match.group(1))
            except Exception as error:
                self._fatal('Unable to run openssl dhparam -text\n', error, '\n', code=ErrorCode.PARAM)
        return 0

    def ecparam_curves(self, ecparam_pem):
        curves = []
        while (ecparam_pem):
            match = re.search(r'(-----BEGIN EC PARAMETERS-----.*?-----END EC PARAMETERS-----)(.*)', ecparam_pem, re.DOTALL)
            if (match):
                ecparam_pem = match.group(2)
                try:
                    output = subprocess.check_output(['openssl', 'ecparam', '-text'], input=match.group(1).encode('ascii'), stderr=subprocess.DEVNULL)
                    match = re.search(r'ASN1 OID: ([^\s]+)\n', output.decode('ascii'))
                    if (match):
                        curves.append(match.group(1))
                except Exception as error:
                    self._fatal('Unable to run openssl ecparam -text\n', error, '\n', code=ErrorCode.PARAM)
            else:
                ecparam_pem = None
        return curves if (curves) else None

    def load_params(self, file_name):
        try:
            pem_data = None
            if (self._directory('param')):
                param_file_path = self._file_path('param', file_name)
                if (os.path.isfile(param_file_path)):
                    with open(param_file_path) as param_file:
                        pem_data = param_file.read()
            if (not pem_data):
                for key_type in self._key_types:
                    certificate_file_path = self._file_path('certificate', file_name, key_type)
                    if (os.path.isfile(certificate_file_path)):
                        with open(certificate_file_path) as certificate_file:
                            pem_data = certificate_file.read()
                        break
        except Exception:
            pass
        if (pem_data):
            match = re.search(r'(-----BEGIN DH PARAMETERS-----.*-----END DH PARAMETERS-----)', pem_data, re.DOTALL)
            dhparam_pem = (match.group(1) + '\n') if (match) else None
            match = re.search(r'(-----BEGIN EC PARAMETERS-----.*-----END EC PARAMETERS-----)', pem_data, re.DOTALL)
            ecparam_pem = (match.group(1) + '\n') if (match) else None
            if (not self.check_dhparam(dhparam_pem)):
                dhparam_pem = None
            if (not self.check_ecparam(ecparam_pem)):
                ecparam_pem = None
            return (dhparam_pem, ecparam_pem)
        return (None, None)

    def save_params(self, file_name, dhparam_pem, ecparam_pem):
        with FileTransaction('param', self._file_path('param', file_name), chmod=0o640) as transaction:
            if (dhparam_pem and ecparam_pem):
                transaction.write(dhparam_pem + '\n' + ecparam_pem)
            else:
                transaction.write(dhparam_pem or ecparam_pem)
        return transaction

    def archive_params(self, file_name, archive_name='', archive_date=None):
        self._archive_file('param', self._file_path('param', file_name), archive_name=archive_name, archive_date=archive_date)

    def _sct_datetime(self, sct_timestamp):
        return datetime.datetime.utcfromtimestamp(sct_timestamp / 1000)

    def _get_ct_log(self, ct_log_name, certificate):
        ct_log = self._config('ct_logs', ct_log_name)
        if (isinstance(ct_log, list)):
            not_after = self._datetime_from_asn1_generaltime(certificate.get_notAfter())
            for log in ct_log:
                start = datetime.datetime.strptime(log.get('start', '2000-01-01T00:00:00Z'), '%Y-%m-%dT%H:%M:%SZ')
                end = datetime.datetime.strptime(log.get('end', '2999-01-01T00:00:00Z'), '%Y-%m-%dT%H:%M:%SZ')
                if ((start <= not_after) and (not_after < end)):
                    return log
            return None
        return ct_log

    def fetch_sct(self, ct_log_name, certificate, chain):
        ct_log = self._get_ct_log(ct_log_name, certificate)
        if (ct_log and ('url' in ct_log)):
            certificates = ([base64.b64encode(self._certificate_bytes(certificate)).decode('ascii')]
                            + [base64.b64encode(self._certificate_bytes(chain_certificate)).decode('ascii') for chain_certificate in chain])
            request_data = json.dumps({'chain': certificates}).encode('ascii')
            request = urllib.request.Request(url=urllib.parse.urljoin(ct_log['url'] + '/', 'ct/v1/add-chain'), data=request_data)
            request.add_header('Content-Type', 'application/json')
            try:
                with urllib.request.urlopen(request) as response:
                    sct = json.loads(response.read().decode('utf-8'))
                    return SCTData(sct.get('sct_version'), sct.get('id'), sct.get('timestamp'), sct.get('extensions'), sct.get('signature'))
            except urllib.error.HTTPError as error:
                if ((400 <= error.code) and (error.code < 500)):
                    self._warn('Unable to retrieve SCT from log ', ct_log_name, ' HTTP error: ', error.code, ' ', error.reason, '\n',
                               self._indent(error.read()), '\n', code=WarningCode.SCT)
                else:
                    self._warn('Unable to retrieve SCT from log ', ct_log_name, ' HTTP error: ', error.code, ' ', error.reason, '\n',
                               code=WarningCode.SCT)
            except urllib.error.URLError as error:
                self._warn('Unable to retrieve SCT from log ', ct_log_name, ' ', error.reason, '\n', code=WarningCode.SCT)
            except Exception as error:
                self._warn('Unable to retrieve SCT from log ', ct_log_name, ' ', error, '\n', code=WarningCode.SCT)
        else:
            self._error('Unknown CT log: ', ct_log_name, '\n', code=ErrorCode.CONFIG)
        return None

    def load_sct(self, file_name, key_type, ct_log_name, certificate):
        try:
            ct_log = self._get_ct_log(ct_log_name, certificate)
            if (ct_log and ('id' in ct_log)):
                sct_file_path = self._file_path('sct', file_name, key_type, ct_log_name=ct_log_name)
                with open(sct_file_path, 'rb') as sct_file:
                    sct = sct_file.read()
                    version, id, timestamp, extensions_len = struct.unpack('>b32sQH', sct[:43])
                    id = base64.b64encode(id).decode('ascii')
                    extensions = base64.b64encode(sct[43:(43 + extensions_len)]).decode('ascii') if (extensions_len) else ''
                    signature = base64.b64encode(sct[43 + extensions_len:]).decode('ascii')

                    if (ct_log['id'] == id):
                        return SCTData(version, id, timestamp, extensions, signature)
                    else:
                        self._detail('SCT ', sct_file_path, ' does not match log id for ', ct_log_name, '\n')
        except Exception:
            pass
        return None

    def save_sct(self, file_name, key_type, ct_log_name, sct_data, certificate):
        ct_log = self._get_ct_log(ct_log_name, certificate)
        if (ct_log):
            with FileTransaction('sct', self._file_path('sct', file_name, key_type, ct_log_name=ct_log_name), chmod=0o640, mode='wb') as transaction:
                extensions = base64.b64decode(sct_data.extensions)
                sct = struct.pack('>b32sQH', sct_data.version, base64.b64decode(sct_data.id), sct_data.timestamp, len(extensions))
                sct += extensions + base64.b64decode(sct_data.signature)
                transaction.write(sct)
            return transaction
        return None

    def archive_sct(self, file_name, key_type, ct_log_name, archive_name='', archive_date=None):
        self._archive_file('sct', self._file_path('sct', file_name, key_type, ct_log_name=ct_log_name), archive_name=archive_name, archive_date=archive_date)

    def ocsp_response_serial_number(self, ocsp_response):
        if ('cert_id' in ocsp_response.response_data['responses'][0]):
            return ocsp_response.response_data['responses'][0]['cert_id']['serial_number'].native
        return None

    def ocsp_response_this_update(self, ocsp_response):
        if ('this_update' in ocsp_response.response_data['responses'][0]):
            return datetime.datetime.strptime(str(ocsp_response.response_data['responses'][0]['this_update']), "%Y%m%d%H%M%SZ")
        return None

    def ocsp_response_next_update(self, ocsp_response):
        if ('next_update' in ocsp_response.response_data['responses'][0]):
            return datetime.datetime.strptime(str(ocsp_response.response_data['responses'][0]['next_update']), "%Y%m%d%H%M%SZ")
        return None

    def ocsp_response_status(self, ocsp_response):
        return ocsp_response.response_data['responses'][0]['cert_status'].name

    def fetch_ocsp_response(self, ocsp_url, ocsp_request, last_update):
        request = urllib.request.Request(url=ocsp_url, data=ocsp_request.dump())
        request.add_header('Content-Type', 'application/ocsp-request')
        request.add_header('Accept', 'application/ocsp-response')
        request.add_header('Host', urllib.parse.urlparse(ocsp_url).hostname)
        if (last_update):
            request.add_header('If-Modified-Since', last_update.strftime('%a, %d %b %Y %H:%M:%S GMT'))
        try:
            with urllib.request.urlopen(request) as response:
                # XXX add validation of response
                return asn1_ocsp.OCSPResponse.load(response.read())
        except urllib.error.HTTPError as error:
            if (last_update and (304 == error.code)):
                return False
            if ((400 <= error.code) and (error.code < 500)):
                self._warn('Unable to retrieve OCSP response from ', ocsp_url, ' HTTP error: ', error.code, ' ', error.reason, '\n',
                           self._indent(error.read()), '\n', code=WarningCode.OCSP)
            else:
                self._warn('Unable to retrieve OCSP response from ', ocsp_url, ' HTTP error: ', error.code, ' ', error.reason, '\n',
                           code=WarningCode.OCSP)
        except urllib.error.URLError as error:
            self._warn('Unable to retrieve OCSP response from ', ocsp_url, ' ', error.reason, '\n', code=WarningCode.OCSP)
        except Exception as error:
            self._warn('Unable to retrieve OCSP response from ', ocsp_url, ' ', error, '\n', code=WarningCode.OCSP)
        return None

    def load_oscp_response(self, file_name, key_type):
        try:
            ocsp_file_path = self._file_path('ocsp', file_name, key_type)
            with open(ocsp_file_path, 'rb') as ocsp_file:
                return asn1_ocsp.OCSPResponse.load(ocsp_file.read())
        except Exception:
            pass
        return None

    def save_ocsp_response(self, file_name, key_type, ocsp_response):
        with FileTransaction('ocsp', self._file_path('ocsp', file_name, key_type), chmod=0o640, mode='wb') as transaction:
            transaction.write(ocsp_response.dump())
        return transaction

    def generate_csr(self, private_key, common_name, alt_names=[], must_staple=False):
        req = OpenSSL.crypto.X509Req()
        req.get_subject().CN = common_name
        extensions = [
            OpenSSL.crypto.X509Extension(
                b'subjectAltName',
                critical=False,
                value=', '.join('DNS:%s' % domain_name for domain_name in alt_names).encode('ascii')
            )
        ]
        if (must_staple):
            extensions.append(self._ocsp_must_staple_extension())
        req.add_extensions(extensions)
        req.set_version(2)
        req.set_pubkey(private_key)
        req.sign(private_key, 'sha256')
        return OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, req)

    def _add_hook(self, hook_name, **kwargs):
        hook = self._config('hooks', hook_name)
        if (hook):
            args = {}
            for key in kwargs:
                args[key] = shlex.quote(kwargs[key])
            if (hook_name not in self.hooks):
                self.hooks[hook_name] = []
            try:
                self.hooks[hook_name].append(hook.format(**args))
            except KeyError as error:
                self._error('Invalid hook specification for ', hook_name, ', unknown key ', error, '\n', code=ErrorCode.PERMISSION)

    def _call_hooks(self):
        for hook_name, hooks in self.hooks.items():
            for hook in hooks:
                try:
                    self._debug('Calling hook ', hook_name, ': ', hook, '\n')
                    self._status(subprocess.check_output(hook, stderr=subprocess.STDOUT, shell=True))
                except subprocess.CalledProcessError as error:
                    self._error('Hook ', hook_name, ' returned error, code: ', error.returncode, '\n', self._indent(error.output), '\n', code=ErrorCode.HOOK)
                except Exception as error:
                    self._error('Failed to call hook ', hook_name, ': ', hook, '\n', self._indent(error), '\n', code=ErrorCode.HOOK)
        self._clear_hooks()

    def _clear_hooks(self):
        self.hooks.clear()

    def _host_in_list(self, host_name, haystack_host_names):
        for haystack_host_name in haystack_host_names:
            if ((host_name == haystack_host_name)
                    or (haystack_host_name.startswith('*.') and ('.' in host_name) and (host_name.split('.', 1)[1] == haystack_host_name[2:]))
                    or (host_name.startswith('*.') and ('.' in haystack_host_name) and (haystack_host_name.split('.', 1)[1] == host_name[2:]))):
                return haystack_host_name
        return None

    def _validate_config(self):
        if ('settings' in self.config):     # backward compat with changed config options
            if (('slave_mode' in self.config['settings']) and ('follower_mode' not in self.config['settings'])):
                self.config['settings']['follower_mode'] = self.config['settings']['slave_mode']

        for section_name, default_section in self._config_defaults.items():
            if (section_name not in self.config):
                self.config[section_name] = default_section
            else:
                for key, value in default_section.items():
                    if (key not in self.config[section_name]):
                        self.config[section_name][key] = value

        temp_dir = self._directory('temp') if (self._directory('temp')) else tempfile.gettempdir()
        self._makedir(temp_dir)
        if (not os.path.exists(temp_dir)):
            self._fatal('Unable to create temp directory: "', temp_dir, '"\n', code=ErrorCode.PERMISSION)
        FileTransaction.temp_dir = temp_dir

        default_verify = self._setting_list('verify')
        if (default_verify):
            verify_list = []
            for verify in default_verify:
                if (verify is None):
                    continue
                if (isinstance(verify, int)):
                    verify = {'port': verify, 'starttls': None, 'protocol': None}
                elif (isinstance(verify, dict)):
                    if ('port' not in verify):
                        self._fatal('verify missing port definition', code=ErrorCode.CONFIG)
                    if (isinstance(verify['port'], str)):
                        try:
                            verify['port'] = int(verify['port'])
                        except Exception:
                            self._fatal('Invalid port definition ', verify['port'], code=ErrorCode.CONFIG)
                    if ('starttls' not in verify):
                        verify['starttls'] = None
                    if ('protocol' not in verify):
                        verify['protocol'] = None
                verify_list.append(verify)
            self.config['settings']['verify'] = verify_list

        private_keys = self.config.get('private_keys', collections.OrderedDict())
        if ('certificates' in self.config):     # convert bare certificate definitions to private key definitions
            certificates = self.config['certificates']
            for certificate_name in certificates:
                if (certificate_name not in private_keys):
                    private_keys[certificate_name] = collections.OrderedDict()
                if ('certificates' not in private_keys[certificate_name]):
                    private_keys[certificate_name]['certificates'] = collections.OrderedDict()
                if (certificate_name not in private_keys[certificate_name]['certificates']):
                    for config_key in ('key_types', 'key_size', 'key_curve', 'key_cipher', 'key_passphrase', 'key_provided',
                                       'expiration_days', 'auto_rollover',
                                       'hpkp_days', 'pin_subdomains', 'hpkp_report_uri'):
                        if ((config_key in certificates[certificate_name]) and (config_key not in private_keys[certificate_name])):
                            private_keys[certificate_name][config_key] = certificates[certificate_name][config_key]
                            del certificates[certificate_name][config_key]
                    private_keys[certificate_name]['certificates'][certificate_name] = certificates[certificate_name]
                else:
                    self._fatal('Certificate ', certificate_name, ' already configured with private key\n', code=ErrorCode.CONFIG)
            del self.config['certificates']

        for private_key_name in private_keys:
            for config_key in ('key_curve', 'key_cipher', 'key_passphrase', 'key_provided',
                               'auto_rollover', 'pin_subdomains', 'hpkp_report_uri'):
                private_keys[private_key_name][config_key] = self._option(private_keys[private_key_name], config_key)
            for config_key in ('key_size', 'expiration_days', 'hpkp_days'):
                private_keys[private_key_name][config_key] = self._option_int(private_keys[private_key_name], config_key)
            for config_key in ('key_types', ):
                private_keys[private_key_name][config_key] = self._option_list(private_keys[private_key_name], config_key)

            key_certificates = private_keys[private_key_name].get('certificates', {})
            if (not key_certificates):
                self._fatal('No certificates defined for private key ', private_key_name, '\n', code=ErrorCode.CONFIG)
            all_certificate_key_types = set()
            private_key_types = list(self._get_key_options(private_keys[private_key_name]).keys())
            for certificate_name in key_certificates:
                if (key_certificates[certificate_name] is None):
                    key_certificates[certificate_name] = {}

                common_name = key_certificates[certificate_name].get('common_name', certificate_name)
                key_certificates[certificate_name]['common_name'] = common_name

                if ('alt_names' not in key_certificates[certificate_name]):
                    registered_name, host_name = self._split_registered_domain(common_name)
                    key_certificates[certificate_name]['alt_names'] = {registered_name: [host_name]}
                elif ('@' in key_certificates[certificate_name]['alt_names']):
                    key_certificates[certificate_name]['alt_names'][common_name] = key_certificates[certificate_name]['alt_names']['@']
                    del key_certificates[certificate_name]['alt_names']['@']
                alt_names = []
                for zone_name in key_certificates[certificate_name]['alt_names']:
                    alt_names += self._get_domain_names(key_certificates[certificate_name]['alt_names'], zone_name)
                if (common_name not in alt_names):
                    self._fatal('Certificate common name "', common_name, '" not listed in alt_names in certificate ', certificate_name, '\n',
                                code=ErrorCode.CONFIG)
                overlap_hosts = alt_names
                for host_name in alt_names:
                    overlap_hosts = overlap_hosts[1:]
                    overlap_host_name = self._host_in_list(host_name, overlap_hosts)
                    if (overlap_host_name):
                        self._fatal('alt_name ', host_name, ' conflicts with ', overlap_host_name, ' in certificate ', certificate_name, '\n',
                                    code=ErrorCode.CONFIG)

                certificate_key_types = self._get_list(key_certificates[certificate_name], 'key_types', private_key_types)
                for key_type in certificate_key_types:
                    if (key_type not in private_key_types):
                        self._fatal('Certificate ', certificate_name, ' defines key type ', key_type, ' that is not present in private key\n',
                                    code=ErrorCode.CONFIG)
                key_certificates[certificate_name]['key_types'] = certificate_key_types
                all_certificate_key_types |= set(certificate_key_types)

                for config_key in ('ocsp_must_staple', ):
                    key_certificates[certificate_name][config_key] = self._option(key_certificates[certificate_name], config_key)
                for config_key in ('dhparam_size', ):
                    key_certificates[certificate_name][config_key] = self._option_int(key_certificates[certificate_name], config_key)
                for config_key in ('services', 'ecparam_curve', 'ct_submit_logs'):
                    key_certificates[certificate_name][config_key] = self._option_list(key_certificates[certificate_name], config_key)

                if ('verify' in key_certificates[certificate_name]):
                    verify_list = []
                    for verify in self._get_list(key_certificates[certificate_name], 'verify'):
                        if (verify is None):
                            continue
                        if (isinstance(verify, int)):
                            verify = {'port': verify, 'starttls': None, 'protocol': None}
                        elif (isinstance(verify, dict)):
                            if ('port' not in verify):
                                self._fatal('verify missing port definition in certificate ', certificate_name, '\n', code=ErrorCode.CONFIG)
                            if (isinstance(verify['port'], str)):
                                try:
                                    verify['port'] = int(verify['port'])
                                except Exception:
                                    self._fatal('Invalid port definition ', verify['port'], ' in certificate ', certificate_name, '\n', code=ErrorCode.CONFIG)
                            if ('starttls' not in verify):
                                verify['starttls'] = None
                            if ('protocol' not in verify):
                                verify['protocol'] = None
                            if ('hosts' in verify):
                                for host_name in self._get_list(verify, 'hosts'):
                                    if (not self._host_in_list(host_name, alt_names)):
                                        self._fatal('Verify host ', host_name, ' not specified in certificate ', certificate_name, '\n', code=ErrorCode.CONFIG)
                        verify_list.append(verify)
                    key_certificates[certificate_name]['verify'] = verify_list
                else:
                    key_certificates[certificate_name]['verify'] = self.config['settings']['verify']
            private_keys[private_key_name]['certificates'] = key_certificates
            private_keys[private_key_name]['key_types'] = [key_type for key_type in private_key_types if (key_type in all_certificate_key_types)]
        self.config['private_keys'] = private_keys

    def _user_agent(self):
        return '{script}/{version} acme-python/{acme_version}'.format(script=self.script_name, version=self.script_version,
                                                                      acme_version=pkg_resources.get_distribution('acme').version)

    def _generate_client_key(self, client_key_path):
        self.client_key = josepy.JWKRSA(key=rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend()))

    def export_client_key(self):
        client_key_pem = self.client_key.key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL, encryption_algorithm=NoEncryption())
        client_key_file_path = 'acmebot_client_key.pem'
        try:
            with open(client_key_file_path, 'w') as client_key_file:
                client_key_file.write(client_key_pem.decode('ascii'))
                self._status('Client key exported to ', client_key_file_path, '\n')
        except Exception as error:
            self._fatal('Unbale to write client key to ', client_key_file_path, '\n', error, '\n', code=ErrorCode.PERMISSION)

    def connect_client(self):
        resource_dir = os.path.join(self.script_dir, self._directory('resource'))
        self._makedir(resource_dir, chmod=0o600)
        generated_client_key = False
        client_key_path = os.path.join(resource_dir, 'client_key.json')
        if (os.path.isfile(client_key_path)):
            with open(client_key_path) as client_key_file:
                self.client_key = josepy.JWKRSA.fields_from_json(json.load(client_key_file))
                self._detail('Loaded clent key ', client_key_path, '\n')
        else:
            self._status('Client key not present, generating\n')
            self._generate_client_key(client_key_path)
            generated_client_key = True

        registration = None
        registration_path = os.path.join(resource_dir, 'registration.json')
        if (os.path.isfile(registration_path)):
            with open(registration_path) as registration_file:
                registration = messages.RegistrationResource.json_loads(registration_file.read())
                self._detail('Loaded registration ', registration_path, '\n')
                acme_url = urllib.parse.urlparse(self._setting('acme_directory_url'))
                reg_url = urllib.parse.urlparse(registration.uri)
                if ((acme_url[0] != reg_url[0]) or (acme_url[1] != reg_url[1])):
                    self._status('ACME service URL has changed, re-registering with new client key\n')
                    registration = None
                    # ACME-ISSUE Resetting the client key should not be necessary, but the new registration comes back empty if we use the old key
                    self._generate_client_key(client_key_path)
                    generated_client_key = True

        if (registration):
            try:
                network = client.ClientNetwork(self.client_key, account=registration, user_agent=self._user_agent(),
                                               verify_ssl=self._setting('acme_directory_verify_ssl'))
                self.acme_client = client.BackwardsCompatibleClientV2(network, self.client_key, self._setting('acme_directory_url'))
            except Exception as error:
                self._fatal("Can't connect to ACME service.\n", error, '\n', code=ErrorCode.ACME)
        else:
            self._detail('Registering client\n')
            try:
                network = client.ClientNetwork(self.client_key, user_agent=self._user_agent(), verify_ssl=self._setting('acme_directory_verify_ssl'))
                self.acme_client = client.BackwardsCompatibleClientV2(network, self.client_key, self._setting('acme_directory_url'))
            except Exception as error:
                self._fatal("Can't connect to ACME service.\n", error, '\n', code=ErrorCode.ACME)

            def _accept_tos(tos):
                if (sys.stdin.isatty() and (not self.args.accept)):
                    self._status('ACME service has the following terms of service:\n', tos, '\n')
                    answer = input('Accept? (Y/n) ')
                    if (answer and not answer.lower().startswith('y')):
                        raise Exception('Terms of service rejected.\n')
                    self._detail('Terms of service accepted.\n')
                else:
                    self._status('Auto-accepting TOS: ', tos, '\n')

            try:
                reg = messages.NewRegistration.from_data(email=self._account('email'))
                registration = self.acme_client.new_account_and_tos(reg, _accept_tos)
            except Exception as error:
                self._fatal("Can't register with ACME service.\n", error, '\n', code=ErrorCode.ACME)

            transactions = []
            if (generated_client_key):
                with FileTransaction('client', client_key_path, chmod=0o600) as client_key_transaction:
                    client_key_transaction.write(json.dumps(self.client_key.fields_to_partial_json()))
                    self._detail('Saved client key ', client_key_path, '\n')
                    transactions.append(client_key_transaction)

            with FileTransaction('registration', registration_path, chmod=0o600) as registration_transaction:
                registration_transaction.write(registration.json_dumps())
                self._detail('Saved registration ', registration_path, '\n')
                transactions.append(registration_transaction)
            try:
                self._commit_file_transactions(transactions, archive_name='client')
            except Exception:
                self._fatal('Unable to save registration to ', registration_path, '\n', code=ErrorCode.PERMISSION)

    def disconnect_client(self):
        if (self.acme_client):
            del self.acme_client

    def _load_public_suffix_list(self):
        if (hasattr(self, '_public_suffixes')):
            return
        resource_dir = os.path.join(self.script_dir, self._directory('resource'))
        self._makedir(resource_dir, chmod=0o600)
        public_suffix_list_path = os.path.join(resource_dir, 'public_suffix_list.dat')
        fetch = True
        last_update = None
        if (os.path.isfile(public_suffix_list_path)):
            last_update = datetime.datetime.utcfromtimestamp(os.path.getmtime(public_suffix_list_path))
            if ((datetime.datetime.utcnow() - last_update).days < 1):
                fetch = False
                self._detail('Cached public suffix list less than one day old\n')
        if (fetch):
            public_suffix_list_url = self._setting('public_suffix_list_url')
            self._detail('Fetching public suffix list from ', public_suffix_list_url, '\n')
            request = urllib.request.Request(url=public_suffix_list_url)
            if (last_update):
                request.add_header('If-Modified-Since', last_update.strftime('%a, %d %b %Y %H:%M:%S GMT'))
            try:
                with urllib.request.urlopen(request) as response:
                    list_bytes = response.read()
                    try:
                        with open(public_suffix_list_path, 'wb') as public_suffix_list_file:
                            public_suffix_list_file.write(list_bytes)
                    except Exception as error:
                        self._fatal('Unable to write public suffix list to ', public_suffix_list_path, '\n', error, '\n', code=ErrorCode.PERMISSION)
            except urllib.error.HTTPError as error:
                if ((400 <= error.code) and (error.code < 500)):
                    self._warn('Unable to retrieve public suffix list from ', public_suffix_list_url, ' HTTP error: ', error.code, ' ', error.reason, '\n',
                               self._indent(error.read()), '\n')
                elif (304 == error.code):
                    now = time.time()
                    os.utime(public_suffix_list_path, (now, now))
                    self._detail('Public suffix list not modified\n')
                else:
                    self._warn('Unable to retrieve public suffix list from ', public_suffix_list_url, ' HTTP error: ', error.code, ' ', error.reason, '\n')
            except AcmeError as error:
                raise error
            except Exception as error:
                self._warn('Unable to retrieve public suffix list from ', public_suffix_list_url, '\n', error, '\n')

        self._public_suffixes = {}
        self._public_suffix_exceptions = {}
        if (os.path.isfile(public_suffix_list_path)):
            with open(public_suffix_list_path, encoding='utf-8') as public_suffix_list_file:
                lines = public_suffix_list_file.read().splitlines()
                for line in lines:
                    line = line.strip()
                    if ((not line) or line.startswith('//')):
                        continue
                    entry = line.split()[:1][0]
                    list = self._public_suffixes
                    if (entry.startswith('!')):
                        entry = entry[1:]
                        list = self._public_suffix_exceptions
                    entry_parts = entry.split('.')
                    for part in reversed(entry_parts):
                        if part not in list:
                            list[part] = {}
                        list = list[part]
        if (not self._public_suffixes):
            self._fatal('Unable to load public suffix list\n', code=ErrorCode.PERMISSION)

    def _split_registered_domain(self, domain_name):
        self._load_public_suffix_list()
        registered_parts = []
        parts = domain_name.split('.')
        list = self._public_suffixes
        exceptions = self._public_suffix_exceptions
        for part in reversed(parts):
            registered_parts.append(part)
            if ((exceptions is not None) and (part in exceptions)):
                exceptions = exceptions[part]
            else:
                exceptions = None
            if ((exceptions is not None) and (not exceptions)):
                break
            if ('*' in list):
                list = list['*']
            elif (part in list):
                list = list[part]
            else:
                break
        registered_name = '.'.join(reversed(registered_parts))
        if (registered_name == domain_name):
            return (registered_name, '@')
        return (registered_name, domain_name[:-(len(registered_name) + 1)])

    def _is_wildcard_auth(self, authorization_resource):
        if (hasattr(authorization_resource.body, 'wildcard')):
            return authorization_resource.body.wildcard
        if (not self._get_challenge(authorization_resource, 'http-01')):    # boulder not currently returning the wildcard field
            return True                                                     # so if no http challenge, presume this is a wildcard auth
        return False

    def _handle_authorizations(self, order, fetch_only, domain_names):
        authorization_resources = {}

        for authorization_resource in order.authorizations:
            domain_name = ('*.' if (self._is_wildcard_auth(authorization_resource)) else '') + authorization_resource.body.identifier.value
            if (messages.STATUS_VALID == authorization_resource.body.status):
                self._detail(domain_name, ' already authorized\n')
            elif (messages.STATUS_PENDING == authorization_resource.body.status):
                if (not fetch_only):
                    authorization_resources[domain_name] = authorization_resource
                    self._debug('Requesting authorization for ', domain_name, '\n')
                else:
                    self._warn(domain_name, ' not authorized\n', code=WarningCode.AUTH)
            else:
                self._fatal('Unexpected status "', authorization_resource.body.status, '" for authorization of ', domain_name, '\n', code=ErrorCode.ACME)

        # set challenge responses
        challenge_types = {}
        challenge_dns_responses = {}
        challenge_http_responses = {}
        for zone_name in domain_names:
            zone_responses = {}
            for domain_name in domain_names[zone_name]:
                if (domain_name in authorization_resources):
                    authorization_resource = authorization_resources[domain_name]
                    identifier = authorization_resource.body.identifier.value
                    http_challenge_directory = self._http_challenge_directory(identifier, zone_name)
                    if (http_challenge_directory):
                        challenge_types[domain_name] = 'http-01'
                        challenge = self._get_challenge(authorization_resource, challenge_types[domain_name])
                        if (not challenge):
                            self._error('Unable to use http-01 challenge for ', domain_name, '\n', code=ErrorCode.ACME)
                            continue
                        challenge_file_path = os.path.join(http_challenge_directory, challenge.chall.encode('token'))
                        self._debug('Setting http acme-challenge for ', domain_name, ' in file ', challenge_file_path, '\n')
                        try:
                            with self._open_file(challenge_file_path, mode='w', chmod=0o644) as challenge_file:
                                challenge_file.write(challenge.validation(self.client_key))
                            challenge_http_responses[domain_name] = challenge_file_path
                            self._add_hook('set_http_challenge', domain=domain_name, challenge_file=challenge_http_responses[domain_name])
                        except Exception as error:
                            self._error('Unable to create acme-challenge file ', challenge_file_path, '\n', self._indent(error), '\n',
                                        code=ErrorCode.PERMISSION)
                    else:
                        challenge_types[domain_name] = 'dns-01'
                        challenge = self._get_challenge(authorization_resource, challenge_types[domain_name])
                        if (not challenge):
                            self._error('Unable to use dns-01 challenge for ', domain_name, '\n', code=ErrorCode.DNS)
                            continue
                        response = challenge.validation(self.client_key)
                        zone_responses[domain_name] = ChallengeTuple(identifier, response)
                        self._debug('Setting DNS for _acme-challenge.', domain_name, ' = "', response, '"\n')
                        self._add_hook('set_dns_challenge', zone=zone_name, domain=domain_name, challenge=response)
            if (zone_responses):
                zone_key = self._zone_key(zone_name)
                if (zone_key):
                    if (self._set_dns_challenges(zone_name, zone_key, zone_responses)):
                        challenge_dns_responses[zone_name] = zone_responses
                else:
                    try:
                        with self._open_file(self._file_path('challenge', zone_name), mode='w', chmod=0o644) as challenge_file:
                            json.dump({domain_name: response.response for domain_name, response in zone_responses.items()}, challenge_file)
                        challenge_dns_responses[zone_name] = zone_responses
                    except Exception as error:
                        self._error('Unable to create acme-challenge file for zone ', zone_name, '\n', self._indent(error), '\n', code=ErrorCode.PERMISSION)
                    if (zone_name in challenge_dns_responses):
                        self._reload_zone(zone_name)
                self._add_hook('dns_zone_update', zone=zone_name)
            self._call_hooks()

        # wait for DNS propagation
        waiting = []
        for zone_name in challenge_dns_responses:
            name_servers = self._get_name_servers(zone_name)
            self._detail('Got name servers ', name_servers, ' for ', zone_name, '\n')
            for name_server in name_servers:
                waiting += [DNSTuple(datetime.datetime.now(), name_server, domain_name,
                                     challenge_dns_responses[zone_name][domain_name].identifier, challenge_dns_responses[zone_name][domain_name].response, 0)
                            for domain_name in challenge_dns_responses[zone_name]]
        while waiting:
            when, name_server, domain_name, identifier, response, attempt_count = heapq.heappop(waiting)
            now = datetime.datetime.now()
            if (now < when):
                seconds = (when - now).seconds
                if (0 < seconds):
                    time.sleep(seconds)
            dns_challenges = self._lookup_dns_challenge(name_server, identifier)
            if (response in dns_challenges):
                self._debug('Challenge present for ', domain_name, ' at ', name_server, '\n')
            else:
                self._detail('Challenge missing for ', domain_name, ' at ', name_server, '\n')
                if (attempt_count < self._setting_int('max_dns_lookup_attempts')):
                    heapq.heappush(waiting, DNSTuple(datetime.datetime.now() + datetime.timedelta(seconds=self._setting_int('dns_lookup_delay')),
                                                     name_server, domain_name, identifier, response, attempt_count + 1))
                else:
                    self._warn('Maximum attempts reached waiting for DNS challenge ', domain_name, ' at ', name_server, '\n', code=WarningCode.DNS)
        if (challenge_dns_responses):
            time.sleep(2)

        # answer challenges
        for domain_name in authorization_resources:
            authorization_resource = authorization_resources[domain_name]
            self._debug('Answering challenge for ', domain_name, '\n')
            challenge = self._get_challenge(authorization_resource, challenge_types[domain_name])
            try:
                self.acme_client.answer_challenge(challenge, challenge.response(self.client_key))
            except Exception as error:
                self._error('Error answering challenge for ', domain_name, ':\n', error, '\n', code=ErrorCode.ACME)

        # poll for authorizations
        waiting = [AuthorizationTuple(datetime.datetime.now(), domain_name, authorization_resource)
                   for domain_name, authorization_resource in authorization_resources.items()]
        attempts = collections.defaultdict(int)
        exhausted = {}
        failed = {}
        while waiting:
            when, domain_name, authorization_resource = heapq.heappop(waiting)
            now = datetime.datetime.now()
            if (now < when):
                seconds = (when - now).seconds
                if (0 < seconds):
                    time.sleep(seconds)
            self._debug('Polling for ', domain_name, '\n')
            try:
                authorization_resource, response = self.acme_client.poll(authorization_resource)
                if (200 != response.status_code):
                    self._warn(response, ' while waiting for domain challenge for ', domain_name, '\n', code=WarningCode.AUTH)
                    heapq.heappush(waiting, AuthorizationTuple(
                        self.acme_client.retry_after(response, default=self._setting_int('authorization_delay')),
                        domain_name, authorization_resource))
                    continue
            except Exception as error:
                self._error('Error polling for authorization for ', domain_name, ':\n', error, '\n', code=ErrorCode.ACME)
                continue

            authorization_resources[domain_name] = authorization_resource
            attempts[authorization_resource] += 1
            if (messages.STATUS_VALID == authorization_resource.body.status):
                if (domain_name in self._failed_auth):
                    self._failed_auth.remove(domain_name)
                self._debug('Authorization received\n')
                continue
            elif (messages.STATUS_INVALID == authorization_resource.body.status):
                error = self._get_challenge(authorization_resource, challenge_types[domain_name]).error
                self._debug('Invalid authorization: ', error.detail if (error) else 'Unknown error', '\n')
                failed[domain_name] = authorization_resource
            elif (messages.STATUS_PENDING == authorization_resource.body.status):
                if (self._setting_int('max_authorization_attempts') < attempts[authorization_resource]):
                    exhausted[domain_name] = authorization_resource
                    self._detail('Giving up\n')
                else:
                    self._detail('Retrying\n')
                    heapq.heappush(waiting, AuthorizationTuple(
                        self.acme_client.retry_after(response, default=self._setting_int('authorization_delay')),
                        domain_name, authorization_resource))
            else:
                self._fatal('Unexpected status "', authorization_resource.body.status, '"\n', code=ErrorCode.ACME)

        # clear challenge responses
        for zone_name in challenge_dns_responses:
            self._debug('Removing DNS _acme-challenges for ', zone_name, '\n')
            for domain_name, challenge in challenge_dns_responses[zone_name].items():
                self._add_hook('clear_dns_challenge', zone=zone_name, domain=domain_name, challenge=challenge.response)
            zone_key = self._zone_key(zone_name)
            if (zone_key):
                self._remove_dns_challenges(zone_name, zone_key, challenge_dns_responses[zone_name])
            else:
                os.remove(self._file_path('challenge', zone_name))
                self._reload_zone(zone_name)
            self._add_hook('dns_zone_update', zone=zone_name)

        for domain_name in challenge_http_responses:
            self._debug('Removing http acme-challenge for ', domain_name, '\n')
            self._add_hook('clear_http_challenge', domain=domain_name, challenge_file=challenge_http_responses[domain_name])
            os.remove(challenge_http_responses[domain_name])
        self._call_hooks()

        for domain_name in failed:
            self._error('Authorization failed for ', domain_name, '\n', code=ErrorCode.AUTH)
            self._failed_auth.add(domain_name)
        for domain_name in exhausted:
            self._warn('Authorization timed out for ', domain_name, '\n', code=WarningCode.AUTH)
            self._failed_auth.add(domain_name)

        if ((ErrorCode.AUTH == self.error_code) and (not self._failed_auth)):  # clear auth error if nothing failed
            self.error_code = ErrorCode.NONE

        order.update(authorizations=[authorization_resource for authorization_resource in authorization_resources.values()])

    def _create_auth_order(self, domain_names):
        if (1 == self.acme_client.acme_version):
            authorizations = []
            for domain_name in domain_names:
                try:
                    authorizations.append(self.acme_client.client.request_domain_challenges(domain_name))
                except Exception as error:
                    self._error('Unable to request authorization for ', domain_name, '\n', self._indent(error), '\n', code=ErrorCode.ACME)
                    continue
            if (authorizations):
                return messages.OrderResource(authorizations=authorizations)
        else:
            identifiers = []

            for domain_name in domain_names:
                identifiers.append(messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=domain_name))

            if (identifiers):
                order = messages.NewOrder(identifiers=identifiers)
                try:
                    response = self.acme_client.client._post(self.acme_client.client.directory['newOrder'], order)
                except Exception as error:
                    self._error('Unable to create authorization order\n', self._indent(error), '\n', code=ErrorCode.ACME)
                    return None
                body = messages.Order.from_json(response.json())
                authorizations = []
                for url in body.authorizations:
                    try:
                        authorizations.append(self.acme_client.client._authzr_from_response(self.acme_client.client._post_as_get(url), uri=url))
                    except Exception as error:
                        self._error('Unable to request authorization for ', domain_name, '\n', self._indent(error), '\n', code=ErrorCode.ACME)
                        continue
                if (authorizations):
                    return messages.OrderResource(body=body, uri=response.headers.get('Location'), authorizations=authorizations)
        return None

    def process_authorizations(self, private_key_names=[]):
        domain_names = collections.OrderedDict()

        # gather domain names from all specified certtificates
        private_keys = self._config('private_keys')
        for private_key_name in private_keys:
            if (private_key_names and (private_key_name not in private_key_names)):
                continue
            key_certificates = private_keys[private_key_name].get('certificates', {})
            for certificate_name in key_certificates:
                for zone_name in key_certificates[certificate_name]['alt_names']:
                    if (zone_name not in domain_names):
                        domain_names[zone_name] = []
                    for domain_name in self._get_domain_names(key_certificates[certificate_name]['alt_names'], zone_name):
                        if (domain_name not in domain_names[zone_name]):
                            domain_names[zone_name].append(domain_name)

        # gather domain names from authorizations
        authorizations = self._config('authorizations')
        for zone_name in authorizations:
            if (zone_name not in domain_names):
                domain_names[zone_name] = []
            for domain_name in self._get_domain_names(authorizations, zone_name):
                if (domain_name not in domain_names[zone_name]):
                    domain_names[zone_name].append(domain_name)

        authorization_groups = []
        for zone_name in domain_names:
            for host_name in domain_names[zone_name]:
                for authorization_host_names in authorization_groups:
                    if ((len(authorization_host_names) < self._setting_int('max_domains_per_order'))
                            and not self._host_in_list(host_name, authorization_host_names)):
                        authorization_host_names.append(host_name)
                        break
                else:
                    authorization_groups.append([host_name])

        for authorization_host_names in authorization_groups:
            order = self._create_auth_order(authorization_host_names)
            if (order):
                self._handle_authorizations(order, False, domain_names)

    def _get_key_options(self, private_key_config):
        key_size = self._option_int(private_key_config, 'key_size')
        key_curve = self._option(private_key_config, 'key_curve')
        key_types = self._get_list(private_key_config, 'key_types', self._key_types)
        key_options = collections.OrderedDict()
        if (key_size and ('rsa' in key_types)):
            key_options['rsa'] = (key_size, )
        if (key_curve and ('ecdsa' in key_types)):
            key_options['ecdsa'] = (key_curve, )
        return key_options

    def _poll_order(self, order):
        response = self.acme_client._post_as_get(order.uri)
        body = messages.Order.from_json(response.json())
        if body.error is not None:
            raise body.error
        return order.update(body=body), response

    def process_certificates(self, auth_fetch_only, private_key_names=[]):
        private_keys = self._config('private_keys')
        updated_key_zones = set()
        processed_keys = []

        for private_key_name in private_keys:
            if (private_key_names and (private_key_name not in private_key_names)):
                continue

            self._debug('Processing private key ', private_key_name, '\n')

            key_options = self._get_key_options(private_keys[private_key_name])
            if (not key_options):
                self._error('No configured private key types for ', private_key_name, '\n', code=ErrorCode.CONFIG)
                continue

            hpkp_days = self._option_int(private_keys[private_key_name], 'hpkp_days')
            expiration_days = self._option_int(private_keys[private_key_name], 'expiration_days')

            rolled_private_key = False
            generated_private_key = False
            changed_private_key = False
            manage_keys = not self._option(private_keys[private_key_name], 'key_provided')

            key_cipher_data = self.key_cipher_data(private_key_name)
            backup_keys = {}
            youngest_key_timestamp = 0
            oldest_key_timestamp = sys.maxsize
            try:
                for key_type in key_options:
                    backup_key_data = self.load_private_key('backup_key', private_key_name, key_type, key_cipher_data)
                    if (backup_key_data.timestamp):
                        youngest_key_timestamp = max(youngest_key_timestamp, backup_key_data.timestamp)
                        oldest_key_timestamp = min(oldest_key_timestamp, backup_key_data.timestamp)
                    backup_keys[key_type] = backup_key_data
            except PrivateKeyError as error:
                self._error('Unable to load backup private key ', error, '\n', code=ErrorCode.KEY)
                continue

            if (0 < youngest_key_timestamp):
                now = datetime.datetime.utcnow()
                youngest_key_age = (now - datetime.datetime.utcfromtimestamp(youngest_key_timestamp))
                oldest_key_age = (now - datetime.datetime.utcfromtimestamp(oldest_key_timestamp))
            else:
                youngest_key_age = None
                oldest_key_age = None

            def _duration(prefix, days):
                if (0 < days):
                    return (prefix + ('1 day' if (1 == days) else (str(days) + ' days')))
                return ('' if (0 == days) else (_duration(' ', -days) + ' ago'))

            if (oldest_key_age is not None):
                self._detail('Private key due for rollover', _duration(' in ', expiration_days - oldest_key_age.days), '\n')

            rollover = False
            if (manage_keys
                and (self.args.rollover
                     or (self._option(private_keys[private_key_name], 'auto_rollover')
                         and self._need_to_rollover(oldest_key_age, expiration_days)))):
                if (self.args.force_rollover or self._safe_to_rollover(youngest_key_age, hpkp_days)):
                    rollover = True
                else:
                    self._warn('A backup private key for ', private_key_name, ' is younger than HPKP duration',
                               _duration(' by ', hpkp_days - youngest_key_age.days), ', rollover skipped\n',
                               'Use "--force" to force key rollover, note that this can brick a web site if HPKP is deployed\n',
                               code=WarningCode.KEY)

            try:
                keys = {key_type: self.load_private_key('private_key', private_key_name, key_type, key_cipher_data) for key_type in key_options}
            except PrivateKeyError as error:
                self._error('Unable to load private key ', error, '\n', code=ErrorCode.KEY)
                continue

            for key_type, options in key_options.items():
                if (keys[key_type].key and not self._private_key_matches_options(key_type, keys[key_type].key, options)):
                    self._info('Private ', key_type.upper(), ' key is not ', self._private_key_descripton(key_type, options), '\n')
                    if manage_keys:
                        if (self.args.force_rollover or self._safe_to_rollover(youngest_key_age, hpkp_days)):
                            keys[key_type] = KeyData(None, None)
                        else:
                            self._warn('A backup private key for ', private_key_name, ' is younger than HPKP duration',
                                       _duration(' by ', hpkp_days - youngest_key_age.days), ', rollover skipped\n',
                                       'Use "--force" to force key rollover, note that this can brick a web site if HPKP is deployed\n',
                                       code=WarningCode.KEY)

            previous_keys = {}
            try:
                for key_type in key_options:
                    previous_keys[key_type] = self.load_private_key('previous_key', private_key_name, key_type, key_cipher_data)
            except PrivateKeyError as error:
                self._error('Unable to load previous private key ', error, '\n', code=ErrorCode.KEY)
                continue

            if manage_keys:
                for key_type in key_options:
                    if (backup_keys[key_type].key and (rollover or not keys[key_type].key)):
                        previous_keys[key_type] = keys[key_type]
                        keys[key_type] = backup_keys[key_type]
                        backup_keys[key_type] = KeyData(None, None)
                        rolled_private_key = True
                        self._add_hook('private_key_rollover', key_name=private_key_name, key_type=key_type,
                                       private_key_file=self._file_path('private_key', private_key_name, key_type),
                                       backup_key_file=self._file_path('backup_key', private_key_name, key_type),
                                       previous_key_file=self._file_path('previous_key', private_key_name, key_type),
                                       passphrase=key_cipher_data.passphrase if (key_cipher_data) else None)
            if (rolled_private_key):
                self._status('Private key rolling over for ', private_key_name, '\n')

            if (not rolled_private_key
                    and self._need_to_rollover(oldest_key_age, expiration_days)
                    and self._safe_to_rollover(youngest_key_age, hpkp_days)):
                if manage_keys:
                    self._warn('Private key for ', private_key_name, ' has expired. Use "--rollover" to replace.\n', code=WarningCode.KEY)
                else:
                    self._warn('Private key for ', private_key_name, ' has expired. Replace with backup key or new key.\n', code=WarningCode.KEY)

            for key_type, options in key_options.items():
                if (not keys[key_type].key):
                    if (manage_keys):
                        self._status('Generating primary ', key_type.upper(), ' key for ', private_key_name, '\n')
                        private_key = self.generate_private_key(key_type, options)
                        keys[key_type] = KeyData(private_key, None)
                        if (private_key):
                            generated_private_key = True
                    else:
                        self._error(key_type.upper(), ' private key for ', private_key_name, ' has not been provided.\n', code=ErrorCode.KEY)

            for key_type, key_data in keys.items():
                if (not key_data.key):
                    del key_options[key_type]

            if (not key_options):
                continue

            issued_certificates = []
            key_certificates = private_keys[private_key_name].get('certificates', {})
            for certificate_name in key_certificates:
                self._debug('Processing certificate ', certificate_name, '\n')

                alt_names = []
                for zone_name in key_certificates[certificate_name]['alt_names']:
                    alt_names += self._get_domain_names(key_certificates[certificate_name]['alt_names'], zone_name)

                common_name = key_certificates[certificate_name].get('common_name', certificate_name)
                certificate_key_types = self._get_list(key_certificates[certificate_name], 'key_types', key_options.keys())
                issue_certificate_key_types = []
                for key_type in certificate_key_types:
                    if ((key_type not in keys) or (not keys[key_type].key)):
                        self._error('No ', key_type.upper(), ' private key available for certificate ', certificate_name, '\n', code=ErrorCode.KEY)
                        continue

                    if ((not rolled_private_key) and (not self.args.renew)):
                        existing_certificate = self.load_certificate('certificate', certificate_name, key_type)
                        if (existing_certificate):
                            replace_certificate = False

                            certificate_common_name = existing_certificate.get_subject().commonName
                            if (common_name != certificate_common_name):
                                self._info('Common name changed for ', key_type.upper(), ' certificate ', certificate_name, ' from ', certificate_common_name,
                                           ' to ', common_name, '\n')
                                replace_certificate = True

                            certificate_alt_names = self.get_alt_names(existing_certificate)
                            new_alt_names = set(alt_names)
                            existing_alt_names = set(certificate_alt_names)
                            if (new_alt_names != existing_alt_names):
                                added_alt_names = new_alt_names - existing_alt_names
                                removed_alt_names = existing_alt_names - new_alt_names
                                added = ', '.join([alt_name for alt_name in alt_names if (alt_name in added_alt_names)])
                                removed = ', '.join([alt_name for alt_name in certificate_alt_names if (alt_name in removed_alt_names)])
                                self._info('Alt names changed for ', key_type.upper(), ' certificate ', certificate_name,
                                           (', adding ' + added) if added else '',
                                           (', removing ' + removed) if removed else '',
                                           '\n')
                                replace_certificate = True

                            if (not self._private_key_matches_certificate(keys[key_type].key, existing_certificate)):
                                self._info(key_type.upper(), ' certificate ', certificate_name, ' public key does not match private key\n')
                                changed_private_key = True
                                replace_certificate = True

                            cert_has_must_staple = self.has_oscp_must_staple(existing_certificate)
                            if (cert_has_must_staple != self._option(key_certificates[certificate_name], 'ocsp_must_staple')):
                                self._info(key_type.upper(), ' certificate ', certificate_name,
                                           ' has' if (cert_has_must_staple) else ' does not have',
                                           ' ocsp_must_staple option\n')
                                replace_certificate = True

                            valid_duration = (self._datetime_from_asn1_generaltime(existing_certificate.get_notAfter())
                                              - datetime.datetime.utcnow())
                            if (valid_duration.days < 0):
                                self._info(key_type.upper(), ' certificate ', certificate_name, ' has expired\n')
                                replace_certificate = True
                            elif (valid_duration.days < self._setting_int('renewal_days')):
                                self._info(key_type.upper(), ' certificate ', certificate_name, ' will expire in ',
                                           (str(valid_duration.days) + ' days') if (valid_duration.days) else 'less than a day',
                                           '\n')
                                replace_certificate = True
                            else:
                                self._debug(key_type.upper(), ' certificate ', certificate_name, ' valid beyond renewal window\n')
                                days_to_renew = valid_duration.days - self._setting_int('renewal_days')
                                self._detail(key_type.upper(), ' certificate due for renewal in ',
                                             days_to_renew, ' day' if (1 == days_to_renew) else ' days', '\n')

                            if (not replace_certificate):
                                continue
                    issue_certificate_key_types.append(key_type)

                domain_names = collections.OrderedDict()
                for zone_name in key_certificates[certificate_name]['alt_names']:
                    if (zone_name not in domain_names):
                        domain_names[zone_name] = []
                    for domain_name in self._get_domain_names(key_certificates[certificate_name]['alt_names'], zone_name):
                        if (domain_name not in domain_names[zone_name]):
                            domain_names[zone_name].append(domain_name)

                for key_type in issue_certificate_key_types:
                    csr_pem = self.generate_csr(keys[key_type].key, common_name, alt_names,
                                                self._option(key_certificates[certificate_name], 'ocsp_must_staple'))
                    self._info('Requesting ', key_type.upper(), ' certificate for ', common_name,
                               (' with alt names: ' + ', '.join(alt_names)) if (alt_names) else '', '\n')
                    try:
                        order = self.acme_client.new_order(csr_pem)
                        self._handle_authorizations(order, auth_fetch_only, domain_names)
                        if (order.uri):
                            order, response = self._poll_order(order)
                            if (messages.STATUS_INVALID == order.body.status):
                                self._error('Unable to issue ', key_type.upper(), ' certificate ', certificate_name, '\n', code=ErrorCode.ACME)
                                continue
                        order = self.acme_client.finalize_order(order,
                                                                datetime.datetime.now() + datetime.timedelta(seconds=self._setting_int('cert_poll_time')))
                        certificate, chain = self.decode_full_chain(order.fullchain_pem)
                    except Exception as error:
                        self._error(key_type.upper(), ' certificate issuance failed\n', self._indent(error), '\n', code=ErrorCode.ACME)
                        if (rolled_private_key):
                            issued_certificates = []    # do not partially install new certificates if private key changed
                            break
                        continue

                    self._debug('New ', key_type.upper(), ' certificate issued\n')
                    issued_certificates.append(CertificateData(certificate_name, key_type, certificate, chain,
                                                               key_certificates[certificate_name]))

            processed_keys.append(PrivateKeyData(private_key_name, key_options, keys, backup_keys, previous_keys,
                                                 generated_private_key, rolled_private_key, changed_private_key, issued_certificates))

        # install keys and certificates
        root_certificates = self.load_root_certificates()

        for private_key_data in processed_keys:
            private_key_name = private_key_data.name

            if ((not private_key_data.issued_certificates) and (private_key_data.generated_key or private_key_data.rolled_key)):
                self._warn('No certificates issued for private key ', private_key_name, ' skipping key updates\n', code=WarningCode.CONFIG)
                self._clear_hooks()
                continue

            generated_backup_key = False
            backup_keys = private_key_data.backup_keys
            for key_type, options in private_key_data.key_options.items():
                if (manage_keys and (not backup_keys[key_type].key)):
                    self._status('Generating backup ', key_type.upper(), ' key for ', private_key_name, '\n')
                    backup_keys[key_type] = KeyData(self.generate_private_key(key_type, options), None)
                    generated_backup_key = True

            transactions = []

            # save private keys
            key_cipher_data = self.key_cipher_data(private_key_name)
            try:
                for key_type in private_key_data.key_options:
                    if (private_key_data.generated_key or private_key_data.rolled_key):
                        transactions.append(self.save_private_key('private_key', private_key_name, key_type,
                                                                  private_key_data.keys[key_type].key, key_cipher_data,
                                                                  timestamp=private_key_data.keys[key_type].timestamp))
                        self._add_hook('private_key_installed', key_name=private_key_name, key_type=key_type,
                                       private_key_file=self._file_path('private_key', private_key_name, key_type),
                                       passphrase=key_cipher_data.passphrase if (key_cipher_data) else None)
                    if (generated_backup_key):
                        transactions.append(self.save_private_key('backup_key', private_key_name, key_type,
                                                                  backup_keys[key_type].key, key_cipher_data,
                                                                  timestamp=backup_keys[key_type].timestamp, chmod=0o600))
                        self._add_hook('backup_key_installed', key_name=private_key_name, key_type=key_type,
                                       backup_key_file=self._file_path('backup_key', private_key_name, key_type),
                                       passphrase=key_cipher_data.passphrase if (key_cipher_data) else None)
                    if (private_key_data.rolled_key and self._directory('previous_key')
                            and (key_type in private_key_data.previous_keys) and private_key_data.previous_keys[key_type].key):
                        transactions.append(self.save_private_key('previous_key', private_key_name, key_type,
                                                                  private_key_data.previous_keys[key_type].key, key_cipher_data,
                                                                  timestamp=private_key_data.previous_keys[key_type].timestamp, chmod=0o600))
                        self._add_hook('previous_key_installed', key_name=private_key_name, key_type=key_type,
                                       previous_key_file=self._file_path('previous_key', private_key_name, key_type),
                                       passphrase=key_cipher_data.passphrase if (key_cipher_data) else None)
            except PrivateKeyError as error:
                self._error('Unable to encrypt private key ', error, '\n', code=ErrorCode.KEY)
                self._clear_hooks()
                continue

            # verify and generate hpkp headers
            generated_hpkp_headers = False
            hpkp_days = self._option_int(private_keys[private_key_name], 'hpkp_days')
            if (0 < hpkp_days) and (self._directory('hpkp')):
                pin_subdomains = self._option(private_keys[private_key_name], 'pin_subdomains')
                hpkp_report_uri = self._option(private_keys[private_key_name], 'hpkp_report_uri')
                keys = ([private_key_data.keys[key_type].key for key_type in private_key_data.key_options if private_key_data.keys[key_type].key]
                        + [private_key_data.backup_keys[key_type].key for key_type in private_key_data.key_options
                           if private_key_data.backup_keys[key_type].key]
                        + [private_key_data.previous_keys[key_type].key for key_type in private_key_data.key_options
                           if private_key_data.previous_keys[key_type].key])
                if ((1 < len(keys))
                        and (private_key_data.generated_key or private_key_data.changed_key or generated_backup_key
                             or not self.hpkp_headers_present(private_key_name, keys, hpkp_days, pin_subdomains, hpkp_report_uri))):
                    self._status('Generating HPKP headers for ', private_key_name, '\n')
                    transactions += self.save_hpkp_headers(private_key_name, keys, hpkp_days, pin_subdomains, hpkp_report_uri)
                    generated_hpkp_headers = True

            # verify DH and EC params for all certificates
            key_certificates = private_keys[private_key_name].get('certificates', {})
            certificate_params = {}
            for certificate_name in key_certificates:
                generated_params = False
                if (not (private_key_data.rolled_key or private_key_data.changed_key)):
                    dhparam_pem, ecparam_pem = self.load_params(certificate_name)
                else:
                    dhparam_pem, ecparam_pem = (None, None)
                hold_dhparam_pem = dhparam_pem
                hold_ecparam_pem = ecparam_pem

                specified_dhparam_size = self._option_int(key_certificates[certificate_name], 'dhparam_size')
                dhparam_size = min(specified_dhparam_size, 2048) if self.args.quick else specified_dhparam_size
                if (dhparam_pem and dhparam_size):
                    existing_dhparam_size = self.dhparam_size(dhparam_pem)
                    if ((existing_dhparam_size != dhparam_size) and (existing_dhparam_size != specified_dhparam_size)):
                        self._info('Diffie-Hellman parameters for ', certificate_name, ' are not ', dhparam_size, ' bits\n')
                        dhparam_pem = None
                if ((not dhparam_pem) and dhparam_size):
                    self._status('Generating ', dhparam_size, ' bit Diffie-Hellman parameters for ', certificate_name, '\n')
                    dhparam_pem = self.generate_dhparam(dhparam_size)
                    if (dhparam_pem):
                        generated_params = True
                    else:
                        self._error('Diffie-Hellman parameters generation failed for ', dhparam_size, ' bits\n', code=ErrorCode.PARAM)
                        dhparam_pem = hold_dhparam_pem

                ecparam_curves = self._option_list(key_certificates[certificate_name], 'ecparam_curve')
                if (ecparam_pem and ecparam_curves and (ecparam_curves != self.ecparam_curves(ecparam_pem))):
                    self._info('Elliptical curve parameters for ', certificate_name, ' are not curve ', ':'.join(ecparam_curves), '\n')
                    ecparam_pem = None
                if ((not ecparam_pem) and (ecparam_curves)):
                    self._status('Generating ', ':'.join(ecparam_curves), ' elliptical curve parameters for ', certificate_name, '\n')
                    ecparam_pem = self.generate_ecparam(ecparam_curves)
                    if (ecparam_pem):
                        generated_params = True
                    else:
                        self._error('Elliptical curve parameters generation failed for curve ', ':'.join(ecparam_curves), '\n', code=ErrorCode.PARAM)
                        ecparam_pem = hold_ecparam_pem

                if ((dhparam_pem or ecparam_pem) and self._directory('param')
                        and (generated_params or not self.params_present(certificate_name, dhparam_pem, ecparam_pem))):
                    transactions.append(self.save_params(certificate_name, dhparam_pem, ecparam_pem))
                    self._add_hook('params_installed', key_name=private_key_name, certificate_name=certificate_name,
                                   params_file=self._file_path('param', certificate_name))
                certificate_params[certificate_name] = (dhparam_pem, ecparam_pem, generated_params)

            # save issued certificates
            saved_certificates = collections.OrderedDict()
            for certificate_data in private_key_data.issued_certificates:
                certificate_name = certificate_data.certificate_name
                dhparam_pem, ecparam_pem, generated_params = certificate_params[certificate_name]

                key_type = certificate_data.key_type
                if (certificate_name not in saved_certificates):
                    saved_certificates[certificate_name] = []
                saved_certificates[certificate_name].append(key_type)

                transactions.append(self.save_certificate('certificate', certificate_name, key_type, certificate_data.certificate,
                                                          chain=certificate_data.chain,
                                                          dhparam_pem=dhparam_pem, ecparam_pem=ecparam_pem))
                self._add_hook('certificate_installed', key_name=private_key_name, key_type=key_type, certificate_name=certificate_name,
                               certificate_file=self._file_path('certificate', certificate_name, key_type))
                if (root_certificates[key_type] and self._directory('full_certificate')):
                    transactions.append(self.save_certificate('full_certificate', certificate_name, key_type, certificate_data.certificate,
                                                              chain=certificate_data.chain, root_certificate=root_certificates[key_type],
                                                              dhparam_pem=dhparam_pem, ecparam_pem=ecparam_pem))
                    self._add_hook('full_certificate_installed', key_name=private_key_name, key_type=key_type, certificate_name=certificate_name,
                                   full_certificate_file=self._file_path('full_certificate', certificate_name, key_type))
                if (certificate_data.chain and self._directory('chain')):
                    transactions.append(self.save_chain(certificate_name, key_type, certificate_data.chain))
                    self._add_hook('chain_installed', key_name=private_key_name, key_type=key_type, certificate_name=certificate_name,
                                   chain_file=self._file_path('chain', certificate_name, key_type))
                try:
                    if (self._directory('full_key')):
                        transactions.append(self.save_private_key('full_key', certificate_name, key_type, private_key_data.keys[key_type].key, key_cipher_data,
                                                                  certificate=certificate_data.certificate, chain=certificate_data.chain,
                                                                  dhparam_pem=dhparam_pem, ecparam_pem=ecparam_pem))
                        self._add_hook('full_key_installed', key_name=private_key_name, key_type=key_type, certificate_name=certificate_name,
                                       full_key_file=self._file_path('full_key', certificate_name, key_type))
                except PrivateKeyError as error:
                    self._error('Unable to encrypt private key ', error, '\n', code=ErrorCode.KEY)
                    continue

            # save any generated params for certs not issued
            for certificate_name in certificate_params:
                dhparam_pem, ecparam_pem, generated_params = certificate_params[certificate_name]
                if (generated_params):
                    certificate_key_types = self._get_list(key_certificates[certificate_name], 'key_types', private_key_data.key_options.keys())
                    for key_type in certificate_key_types:
                        if ((not private_key_data.keys[key_type].key)
                                or ((certificate_name in saved_certificates) and (key_type in saved_certificates[certificate_name]))):
                            continue
                        # XXX also should test for missing full cert or full key and save if configured
                        certificate = self.load_certificate('certificate', certificate_name, key_type)
                        if (certificate):
                            if (certificate_name not in saved_certificates):
                                saved_certificates[certificate_name] = []
                            saved_certificates[certificate_name].append(key_type)

                            chain = self.load_chain(certificate_name, key_type)

                            transactions.append(self.save_certificate('certificate', certificate_name, key_type, certificate,
                                                                      chain=chain,
                                                                      dhparam_pem=dhparam_pem, ecparam_pem=ecparam_pem))
                            self._add_hook('certificate_installed', key_name=private_key_name, key_type=key_type, certificate_name=certificate_name,
                                           certificate_file=self._file_path('certificate', certificate_name, key_type))
                            if (root_certificates[key_type] and self._directory('full_certificate')):
                                transactions.append(self.save_certificate('full_certificate', certificate_name, key_type, certificate,
                                                                          chain=chain, root_certificate=root_certificates[key_type],
                                                                          dhparam_pem=dhparam_pem, ecparam_pem=ecparam_pem))
                                self._add_hook('full_certificate_installed', key_name=private_key_name, key_type=key_type, certificate_name=certificate_name,
                                               full_certificate_file=self._file_path('full_certificate', certificate_name, key_type))
                            try:
                                if (self._directory('full_key')):
                                    transactions.append(self.save_private_key('full_key', certificate_name, key_type,
                                                                              private_key_data.keys[key_type].key, key_cipher_data,
                                                                              certificate=certificate, chain=chain,
                                                                              dhparam_pem=dhparam_pem, ecparam_pem=ecparam_pem))
                                    self._add_hook('full_key_installed', key_name=private_key_name, key_type=key_type, certificate_name=certificate_name,
                                                   full_key_file=self._file_path('full_key', certificate_name, key_type))
                            except PrivateKeyError as error:
                                self._error('Unable to encrypt private key ', error, '\n', code=ErrorCode.KEY)
                                continue

            try:
                self._commit_file_transactions(transactions, archive_name=private_key_name)
                self._call_hooks()
                if (private_key_data.generated_key or private_key_data.rolled_key or generated_backup_key):
                    self._status('Private keys for ', private_key_name, ' installed\n')
                for certificate_name in saved_certificates:
                    for key_type in saved_certificates[certificate_name]:
                        self._status(key_type.upper(), ' certificate ', certificate_name, ' installed\n')
                        self.update_services(self._option_list(key_certificates[certificate_name], 'services'))
                        if (not self._setting('follower_mode')):
                            for zone_name in key_certificates[certificate_name]['alt_names']:
                                if (not self._zone_key(zone_name)):
                                    updated_key_zones.add(zone_name)
                if (generated_backup_key or generated_hpkp_headers):    # reload services for all certificates
                    for certificate_name in key_certificates:
                        self.update_services(self._option_list(key_certificates[certificate_name], 'services'))

            except Exception as error:
                self._error('Unable to install keys and certificates for ', private_key_name, '\n', self._indent(error), '\n', code=ErrorCode.PERMISSION)
                self._clear_hooks()

        for zone_name in updated_key_zones:
            self._reload_zone(zone_name, critical=False)

    def revoke_certificates(self, private_key_names):
        private_keys = self._config('private_keys')
        updated_key_zones = set()
        updated_tlsa_zones = collections.OrderedDict()

        for private_key_name in private_key_names:
            if (private_key_name in private_keys):
                key_options = self._get_key_options(private_keys[private_key_name])
                if (not key_options):
                    self._error('No configured private key types for ', private_key_name, '\n', code=ErrorCode.CONFIG)
                    continue

                key_certificates = private_keys[private_key_name].get('certificates', {})
                revoked_certificates = []
                certificate_count = 0
                for certificate_name in key_certificates:
                    certificate_key_types = self._get_list(key_certificates[certificate_name], 'key_types', key_options.keys())
                    for key_type in certificate_key_types:
                        certificate = self.load_certificate('certificate', certificate_name, key_type)
                        if (certificate):
                            certificate_count += 1
                            try:
                                self.acme_client.revoke(josepy.ComparableX509(certificate), 0)
                                revoked_certificates.append((certificate_name, key_type))
                                self._status(key_type.upper(), ' certificate ', certificate_name, ' revoked\n')
                            except Exception as error:
                                self._error('Unable to revoke ', key_type.upper(), ' certificate ', certificate_name, '\n', self._indent(error), '\n',
                                            code=ErrorCode.ACME)
                        else:
                            self._error(key_type.upper(), ' certificate ', certificate_name, ' not found\n', code=ErrorCode.CONFIG)

                archive_date = datetime.datetime.now()
                processed_tlsa = set()
                for certificate_name, key_type in revoked_certificates:
                    self.archive_certificate('certificate', certificate_name, key_type, archive_name=private_key_name, archive_date=archive_date)
                    self.archive_certificate('full_certificate', certificate_name, key_type, archive_name=private_key_name, archive_date=archive_date)
                    self.archive_chain(certificate_name, key_type, archive_name=private_key_name, archive_date=archive_date)
                    self.archive_private_key('full_key', certificate_name, key_type, archive_name=private_key_name, archive_date=archive_date)
                    self.archive_params(certificate_name, archive_name=private_key_name, archive_date=archive_date)
                    ct_submit_logs = self._option_list(key_certificates[certificate_name], 'ct_submit_logs')
                    for ct_log_name in ct_submit_logs:
                        self.archive_sct(certificate_name, key_type, ct_log_name, archive_name=private_key_name, archive_date=archive_date)

                    if (not self._setting('follower_mode')):
                        for zone_name in key_certificates[certificate_name]['alt_names']:
                            if (not self._zone_key(zone_name)):
                                updated_key_zones.add(zone_name)
                    if (certificate_name not in processed_tlsa):
                        processed_tlsa.add(certificate_name)

                        tlsa_records = key_certificates[certificate_name].get('tlsa_records', {})
                        for zone_name in tlsa_records:
                            if (self._zone_key(zone_name)):
                                if (zone_name not in updated_tlsa_zones):
                                    updated_tlsa_zones[zone_name] = []
                                updated_tlsa_zones[zone_name] += self._tlsa_data(self._get_list(tlsa_records, zone_name))
                            else:
                                self._error('No update key configured for zone ', zone_name, ', unable to remove TLSA records\n', code=ErrorCode.CONFIG)

                if (len(revoked_certificates) == certificate_count):
                    for key_type in key_options:
                        self.archive_private_key('private_key', private_key_name, key_type, archive_name=private_key_name, archive_date=archive_date)
                        self.archive_private_key('previous_key', private_key_name, key_type, archive_name=private_key_name, archive_date=archive_date)
                        self.archive_hpkp_headers(private_key_name, archive_name=private_key_name, archive_date=archive_date)
            else:
                self._error(private_key_name, ' is not a configured private key\n', code=ErrorCode.CONFIG)

        for zone_name in updated_key_zones:
            self._reload_zone(zone_name, critical=False)
        for zone_name in updated_tlsa_zones:
            self._remove_tlsa_records(zone_name, self._zone_key(zone_name), updated_tlsa_zones[zone_name])

    def update_tlsa_records(self, private_key_names):
        private_keys = self._config('private_keys')
        tlsa_zones = collections.OrderedDict()

        root_certificates = list(self.load_root_certificates().values())

        for private_key_name in private_keys:
            if (private_key_names and (private_key_name not in private_key_names)):
                continue

            key_options = self._get_key_options(private_keys[private_key_name])
            if (not key_options):
                self._error('No configured private key types for ', private_key_name, '\n', code=ErrorCode.CONFIG)
                continue

            keys = []
            key_cipher_data = self.key_cipher_data(private_key_name)
            try:
                for key_type in key_options:
                    keys.append((key_type, self.load_private_key('private_key', private_key_name, key_type, key_cipher_data).key))
                    keys.append((key_type, self.load_private_key('backup_key', private_key_name, key_type, key_cipher_data).key))
                    previous_key = self.load_private_key('previous_key', private_key_name, key_type, key_cipher_data).key
                    if (previous_key):
                        keys.append((key_type, previous_key))
            except PrivateKeyError as error:
                self._error('Unable to load private key ', error, '\n', code=ErrorCode.KEY)
                continue

            key_certificates = private_keys[private_key_name].get('certificates', {})
            for certificate_name in key_certificates:
                tlsa_records = key_certificates[certificate_name].get('tlsa_records', {})
                if (tlsa_records):
                    certificates = []
                    chain = []
                    certificate_key_types = self._get_list(key_certificates[certificate_name], 'key_types', key_options.keys())
                    for key_type in certificate_key_types:
                        certificate = self.load_certificate('certificate', certificate_name, key_type)
                        if (not certificate):
                            self._error(key_type.upper(), ' certificate ', certificate_name, ' not found\n', code=ErrorCode.CONFIG)
                            continue
                        certificates.append(certificate)
                        chain += self.load_chain(certificate_name, key_type)

                    for zone_name in tlsa_records:
                        if (self._zone_key(zone_name)):
                            if (zone_name not in tlsa_zones):
                                tlsa_zones[zone_name] = []
                            tlsa_zones[zone_name] += self._tlsa_data(self._get_list(tlsa_records, zone_name), certificates=certificates,
                                                                     chain=(chain + root_certificates),
                                                                     private_keys=[key for key_type, key in keys if (key_type in certificate_key_types)])
                        else:
                            self._error('No update key configured for zone ', zone_name, ', unable to set TLSA records\n', code=ErrorCode.CONFIG)

        for zone_name in tlsa_zones:
            self._set_tlsa_records(zone_name, self._zone_key(zone_name), tlsa_zones[zone_name])
            self._add_hook('dns_zone_update', zone=zone_name)
        self._call_hooks()

    def update_signed_certificate_timestamps(self, private_key_names):
        if (not self._directory('sct')):
            return

        private_keys = self._config('private_keys')
        for private_key_name in private_keys:
            if (private_key_names and (private_key_name not in private_key_names)):
                continue

            key_options = self._get_key_options(private_keys[private_key_name])
            if (not key_options):
                self._error('No configured private key types for ', private_key_name, '\n', code=ErrorCode.CONFIG)
                continue

            transactions = []
            key_certificates = private_keys[private_key_name].get('certificates', {})
            for certificate_name in key_certificates:
                ct_submit_logs = self._option_list(key_certificates[certificate_name], 'ct_submit_logs')
                if (ct_submit_logs):
                    certificate_key_types = self._get_list(key_certificates[certificate_name], 'key_types', key_options.keys())
                    for key_type in certificate_key_types:
                        certificate = self.load_certificate('certificate', certificate_name, key_type)
                        if (certificate):
                            chain = self.load_chain(certificate_name, key_type)
                            for ct_log_name in ct_submit_logs:
                                sct_data = self.fetch_sct(ct_log_name, certificate, chain)
                                if (sct_data):
                                    self._detail(ct_log_name, ' has SCT for ', key_type.upper(), ' certificate ', certificate_name, ' at ',
                                                 self._sct_datetime(sct_data.timestamp).isoformat(), '\n')
                                existing_sct_data = self.load_sct(certificate_name, key_type, ct_log_name, certificate)
                                if (sct_data and ((not existing_sct_data) or (sct_data != existing_sct_data))):
                                    self._info('Saving Signed Certificate Timestamp for ', key_type.upper(), ' certificate ', certificate_name,
                                               ' from ', ct_log_name, '\n')
                                    transactions.append(self.save_sct(certificate_name, key_type, ct_log_name, sct_data, certificate))
                                    self._add_hook('sct_installed', key_name=private_key_name, key_type=key_type,
                                                   certificate_name=certificate_name, ct_log_name=ct_log_name,
                                                   sct_file=self._file_path('sct', certificate_name, key_type, ct_log_name=ct_log_name))
                                    self.update_services(self._option_list(key_certificates[certificate_name], 'services'))
                        else:
                            self._error(key_type.upper(), ' certificate ', certificate_name, ' not found\n', code=ErrorCode.CONFIG)

            try:
                self._commit_file_transactions(transactions, archive_name=None)
                self._call_hooks()
            except Exception as error:
                self._error('Unable to save Signed Certificate Timestamps for ', private_key_name, '\n', self._indent(error), '\n', code=ErrorCode.PERMISSION)
                self._clear_hooks()

    def update_ocsp_responses(self, private_key_names):
        if (not self._directory('ocsp')):
            return

        root_certificates = self.load_root_certificates()
        default_ocsp_responder_urls = self._setting_list('ocsp_responder_urls')

        private_keys = self._config('private_keys')
        for private_key_name in private_keys:
            if (private_key_names and (private_key_name not in private_key_names)):
                continue

            key_options = self._get_key_options(private_keys[private_key_name])
            if (not key_options):
                self._error('No configured private key types for ', private_key_name, '\n', code=ErrorCode.CONFIG)
                continue

            transactions = []
            key_certificates = private_keys[private_key_name].get('certificates', {})
            for certificate_name in key_certificates:
                certificate_key_types = self._get_list(key_certificates[certificate_name], 'key_types', key_options.keys())
                for key_type in certificate_key_types:
                    certificate = self.load_certificate('certificate', certificate_name, key_type)
                    if (not certificate):
                        self._error(key_type.upper(), ' certificate ', certificate_name, ' not found\n', code=ErrorCode.CONFIG)
                        continue
                    asn1crypto_certificate = asn1_x509.Certificate.load(self._certificate_bytes(certificate))

                    ocsp_response = self.load_oscp_response(certificate_name, key_type)
                    if (ocsp_response and ('good' == self.ocsp_response_status(ocsp_response).lower())
                            and (self.ocsp_response_serial_number(ocsp_response) == asn1crypto_certificate.serial_number)):
                        last_update = self.ocsp_response_this_update(ocsp_response)
                        self._detail('Have stapled OCSP response for ', key_type.upper(), ' certificate ', certificate_name,
                                     ' updated at ', last_update.strftime('%Y-%m-%d %H:%M:%S UTC'), '\n')
                    else:
                        last_update = None

                    ocsp_urls = (asn1crypto_certificate.ocsp_urls
                                 or self._get_list(key_certificates[certificate_name], 'ocsp_responder_urls', default_ocsp_responder_urls))
                    if (ocsp_urls):
                        chain = self.load_chain(certificate_name, key_type)
                        issuer_certificate = chain[0] if (chain) else root_certificates[key_type]
                        issuer_asn1_certificate = asn1_x509.Certificate.load(self._certificate_bytes(issuer_certificate))

                        tbs_request = asn1_ocsp.TBSRequest({
                            'request_list': [
                                {
                                    'req_cert': {
                                        'hash_algorithm': {'algorithm': 'sha1'},
                                        'issuer_name_hash': asn1crypto_certificate.issuer.sha1,
                                        'issuer_key_hash': issuer_asn1_certificate.public_key.sha1,
                                        'serial_number': asn1crypto_certificate.serial_number,
                                    },
                                    'single_request_extensions': None
                                }
                            ],
                            'request_extensions': None  # [{'extn_id': 'nonce', 'critical': False, 'extn_value': os.urandom(16)}]
                            # we don't appear to be getting the nonce back, so don't send it
                        })
                        ocsp_request = asn1_ocsp.OCSPRequest({
                            'tbs_request': tbs_request,
                            'optional_signature': None
                        })

                        for ocsp_url in ocsp_urls:
                            ocsp_response = self.fetch_ocsp_response(ocsp_url, ocsp_request, last_update)
                            if (ocsp_response):
                                if ('successful' == ocsp_response['response_status'].native):
                                    ocsp_status = self.ocsp_response_status(ocsp_response)
                                    this_update = self.ocsp_response_this_update(ocsp_response)
                                    self._detail('Retrieved OCSP status "', ocsp_status.upper(), '" for ', key_type.upper(), ' certificate ', certificate_name,
                                                 ' from ', ocsp_url,
                                                 ' updated at ', this_update.strftime('%Y-%m-%d %H:%M:%S UTC'), '\n')
                                    if ('good' == ocsp_status.lower()):
                                        if (this_update == last_update):
                                            self._debug('OCSP response for ', key_type.upper(), ' certificate ', certificate_name,
                                                        ' from ', ocsp_url,
                                                        ' has not been updated\n')
                                            break
                                        self._info('Saving OCSP response for ', key_type.upper(), ' certificate ', certificate_name,
                                                   ' from ', ocsp_url, '\n')
                                        transactions.append(self.save_ocsp_response(certificate_name, key_type, ocsp_response))
                                        self._add_hook('ocsp_installed', key_name=private_key_name, key_type=key_type,
                                                       certificate_name=certificate_name,
                                                       ocsp_file=self._file_path('ocsp', certificate_name, key_type))
                                        self.update_services(self._option_list(key_certificates[certificate_name], 'services'))
                                        break
                                    else:
                                        self._warn(key_type.upper(), ' certificate ', certificate_name, ' has OCSP status "', ocsp_status.upper(), '"',
                                                   ' from ', ocsp_url,
                                                   ' updated at ', this_update.strftime('%Y-%m-%d %H:%M:%S UTC'), '\n',
                                                   code=WarningCode.OCSP)
                                else:
                                    self._warn(key_type.upper(), ' certificate ', certificate_name,
                                               ' OCSP request received "', ocsp_response['response_status'].native, '"',
                                               ' from ', ocsp_url, '\n',
                                               code=WarningCode.OCSP)
                            elif (ocsp_response is False):
                                self._debug('OCSP response for ', key_type.upper(), ' certificate ', certificate_name,
                                            ' from ', ocsp_url,
                                            ' has not been updated\n')
                                break
                        else:
                            self._warn('Unable to retrieve OCSP response for ', key_type.upper(), ' certificate ', certificate_name, '\n',
                                       code=WarningCode.OCSP)
                    else:
                        self._warn('No OCSP responder URL for ', key_type.upper(), ' certificate ', certificate_name, ' and no default set\n',
                                   code=WarningCode.CONFIG)

            try:
                self._commit_file_transactions(transactions, archive_name=None)
                self._call_hooks()
            except Exception as error:
                self._error('Unable to save OCSP responses for ', private_key_name, '\n', self._indent(error), '\n', code=ErrorCode.PERMISSION)
                self._clear_hooks()

    def _send_starttls(self, type, sock, host_name):
        sock.settimeout(30)
        type = type.lower()
        if ('smtp' == type):
            self._detail('SMTP: ', sock.recv(4096))
            sock.send(b'ehlo acmebot.org\r\n')
            buffer = sock.recv(4096)
            self._detail('SMTP: ', buffer)
            if (b'STARTTLS' not in buffer):
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
                raise Exception('STARTTLS not supported on server')
            sock.send(b'starttls\r\n')
            self._detail('SMTP: ', sock.recv(4096))
        elif ('pop3' == type):
            self._detail('POP3: ', sock.recv(4096))
            sock.send(b'STLS\r\n')
            self._detail('POP3: ', sock.recv(4096))
        elif ('imap' == type):
            self._detail('IMAP: ', sock.recv(4096))
            sock.send(b'a001 STARTTLS\r\n')
            self._detail('IMAP: ', sock.recv(4096))
        elif ('ftp' == type):
            self._detail('FTP: ', sock.recv(4096))
            sock.send(b'AUTH TLS\r\n')
            self._detail('FTP: ', sock.recv(4096))
        elif ('xmpp' == type):
            sock.send('<stream:stream xmlns:stream="http://etherx.jabber.org/streams" '
                      'xmlns="jabber:client" to="{host}" version="1.0">\n'.format(host=host_name).encode('ascii'))
            self._detail('XMPP: ', sock.recv(4096), '\n')
            sock.send(b'<starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>')
            self._detail('XMPP: ', sock.recv(4096), '\n')
        elif ('sieve' == type):
            buffer = sock.recv(4096)
            self._detail('SIEVE: ', buffer)
            if (b'"STARTTLS"' not in buffer):
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
                raise Exception('STARTTLS not supported on server')
            sock.send(b'StartTls\r\n')
            self._detail('SIEVE: ', sock.recv(4096))
        elif ('ldap' == type):
            self._detail('Sending LDAP StartTLS\n')
            sock.send(b'\x30\x1d\x02\x01\x01\x77\x18\x80\x16\x31\x2e\x33\x2e\x36\x2e\x31\x2e\x34\x2e\x31\x2e\x31\x34\x36\x36\x2e\x32\x30\x30\x33\x37')
            buffer = sock.recv(4096)
            if (b'\x0a\x01\x00' != buffer[7:10]):
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
                raise Exception('STARTTLS not supported on server')
            self._detail('LDAP: ', buffer.hex(), '\n')
        else:
            sock.shutdown()
            sock.close()
            raise Exception('Unsuppoprted STARTTLS type: ' + type)
        sock.settimeout(None)

    def _get_http_headers(self, sock, host_name):
        try:
            sock.send('HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n'.format(host=host_name).encode('ascii'))
            http_bytes = sock.recv(16384)
            self._detail('HTTP: ', http_bytes)

            headers = {}
            lines = http_bytes.decode('utf-8').split('\n')
            for line in lines[1:]:
                if (not line):
                    break
                if (':' in line):
                    key, value = line.split(':', 1)
                    headers[key.lower().strip()] = value.strip()
            return headers
        except Exception as error:
            self._warn('Unable to fetch http headers from ', host_name, '\n', self._indent(error), '\n')
        return None

    def _get_protocol_info(self, protocol, sock, host_name):
        if ('http' == protocol.lower()):
            headers = self._get_http_headers(sock, host_name)
            if (headers is not None):
                protocol_info = {}
                if ('public-key-pins' in headers):
                    pin_header = headers['public-key-pins']
                    pins = []
                    for pin in pin_header.split(';'):
                        pin = pin.strip()
                        if (pin.startswith('pin-') and ('=' in pin)):
                            parts = pin.split('=', 1)
                            pins.append((parts[0][4:], base64.b64decode(parts[1].strip('"\''))))
                    protocol_info['public_key_pins'] = pins
                return protocol_info
            else:
                return None
        else:
            raise Exception('Unsupported verification protocol: ' + protocol)

    def _fetch_tls_info(self, addr, ssl_context, key_type, host_name, starttls, protocol):
        sock = socket.socket(addr[0], socket.SOCK_STREAM)
        sock.connect(addr[4])

        if (starttls):
            self._send_starttls(starttls, sock, host_name)

        def _process_ocsp(conn, ocsp_data, data):
            conn.get_app_data()['ocsp'] = asn1_ocsp.OCSPResponse.load(ocsp_data) if (b'' != ocsp_data) else None
            return True

        app_data = {'has_ocsp': False}
        ssl_context.set_ocsp_client_callback(_process_ocsp)
        ssl_sock = OpenSSL.SSL.Connection(ssl_context, sock)
        ssl_sock.set_app_data(app_data)
        ssl_sock.set_connect_state()
        ssl_sock.set_tlsext_host_name(host_name.encode('ascii'))
        ssl_sock.request_ocsp()
        ssl_sock.do_handshake()
        self._debug('Connected to ', ssl_sock.get_servername(), ', protocol ', ssl_sock.get_protocol_version_name(),
                    ', cipher ', ssl_sock.get_cipher_name(),
                    ', OCSP Staple ', self.ocsp_response_status(app_data['ocsp']).upper() if (app_data['ocsp']) else 'missing',
                    '\n')
        installed_certificates = ssl_sock.get_peer_cert_chain()

        protocol_info = self._get_protocol_info(protocol, ssl_sock, host_name) if (protocol) else None

        ssl_sock.shutdown()
        ssl_sock.close()
        return installed_certificates, app_data['ocsp'], protocol_info

    def _tlsa_record_matches(self, tlsa_record, certificate, chain, root_certificate):
        matches = []
        usage, selector, matching_type, data = tlsa_record.split(' ', 4)
        if ('0' == usage) or ('2' == usage):    # match record to chain + root
            certificates = chain.copy()
            if (root_certificate):
                certificates.append(root_certificate)

            if ('0' == selector):
                for chain_certificate in certificates:
                    matches.append(self._certificate_bytes(chain_certificate))
            elif ('1' == selector):
                for chain_certificate in certificates:
                    matches.append(self._certificate_public_key_bytes(chain_certificate))
            else:
                self._error('ERROR: unknown selector in TLSA record ', tlsa_record, '\n', code=ErrorCode.CONFIG)
        elif ('1' == usage) or ('3' == usage):  # match record to certifitcate
            if ('0' == selector):
                matches.append(self._certificate_bytes(certificate))
            elif ('1' == selector):
                matches.append(self._certificate_public_key_bytes(certificate))
            else:
                self._error('ERROR: unknown selector in TLSA record ', tlsa_record, '\n', code=ErrorCode.CONFIG)
        else:
            self._error('ERROR: unknown usage in TLSA record ', tlsa_record, '\n', code=ErrorCode.CONFIG)

        for match in matches:
            if ('0' == matching_type):  # entire certificate/key
                if (binascii.hexlify(match).decode('ascii') == data):
                    return True
            elif ('1' == matching_type):    # sha256 of data
                if (hashlib.sha256(match).hexdigest() == data):
                    return True
            elif ('2' == matching_type):    # sha512 of data
                if (hashlib.sha512(match).hexdigest() == data):
                    return True
            else:
                self._error('ERROR: unknown matching type in TLSA record ', tlsa_record, '\n', code=ErrorCode.CONFIG)
        return False

    def _verify_certificate_installation(self, certificate_name, certificate, chain, root_certificate,
                                         key_type, host_name, port_number, starttls, cipher_list, protocol, keys):
        ssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD | OpenSSL.SSL.TLSv1_2_METHOD)
        ssl_context.set_cipher_list(cipher_list)

        try:
            if (host_name.startswith('*.')):
                host_name = 'wildcard-test-{random}.{host_name}'.format(random=self._random_string(10), host_name=host_name[2:])
            addr_info = socket.getaddrinfo(host_name, port_number, proto=socket.IPPROTO_TCP)
        except Exception as error:
            self._error('ERROR: Unable to get address for ', host_name, '\n', self._indent(error), '\n', code=ErrorCode.DNS)
            return

        tlsa_records = self._lookup_tlsa_records(host_name, port_number, 'tcp')
        if tlsa_records:
            self._debug('Found TLSA records for ', host_name, ':', port_number, '\n')
            for tlsa_record in tlsa_records:
                self._detail('    ', tlsa_record, '\n')
        else:
            self._detail('No TLSA records found for ', host_name, ':', port_number, '\n')

        for addr in addr_info:
            host_desc = host_name + ' at ' + (('[' + addr[4][0] + ']') if (socket.AF_INET6 == addr[0]) else addr[4][0]) + ':' + str(port_number)
            try:
                self._debug('Connecting to ', host_desc, ' with ', key_type.upper(), ' ciphers\n')
                installed_certificates, ocsp_staple, protocol_info = self._fetch_tls_info(addr, ssl_context, key_type, host_name, starttls, protocol)
                if (self.has_oscp_must_staple(certificate)):
                    attempts = 1
                    while ((not ocsp_staple) and (attempts < self._setting_int('max_ocsp_verify_attempts'))):
                        time.sleep(self._setting_int('ocsp_verify_retry_delay'))
                        self._detail('Retrying to fetch OCSP staple\n')
                        installed_certificates, ocsp_staple, protocol_info = self._fetch_tls_info(addr, ssl_context, key_type, host_name, starttls, protocol)
                        attempts += 1

                installed_certificate = installed_certificates[0]
                installed_chain = installed_certificates[1:]
                if (self._certificates_match(certificate, installed_certificate)):
                    self._info(key_type.upper(), ' certificate ', certificate_name, ' present on ', host_desc, '\n', color='green')
                else:
                    self._error('ERROR: ', key_type.upper(), ' certificate "',
                                installed_certificate.get_subject().commonName, '" mismatch on ', host_desc, '\n', code=ErrorCode.VERIFY)
                if (len(chain) != len(installed_chain)):
                    self._error('ERROR: ', key_type.upper(), ' certificate chain length mismatch on ', host_desc, ', got ', len(installed_chain),
                                ' intermediate(s), expected ', len(chain), '\n', code=ErrorCode.VERIFY)
                else:
                    for intermediate, installed_intermediate in zip(chain, installed_chain):
                        if (self._certificates_match(intermediate, installed_intermediate)):
                            self._info('Intermediate ', key_type.upper(), ' certificate "', intermediate.get_subject().commonName,
                                       '" present on ', host_desc, '\n', color='green')
                        else:
                            self._error('ERROR: Intermediate ', key_type.upper(), ' certificate "', installed_intermediate.get_subject().commonName,
                                        '" mismatch on ', host_desc, '\n', code=ErrorCode.VERIFY)
                if (ocsp_staple):
                    ocsp_status = self.ocsp_response_status(ocsp_staple)
                    if ('good' == ocsp_status.lower()):
                        self._info('OCSP staple status is GOOD on ', host_desc, '\n', color='green')
                    else:
                        self._error('ERROR: OCSP staple has status: ', ocsp_status.upper(), ' on ', host_desc, '\n', code=ErrorCode.VERIFY)
                else:
                    if (self.has_oscp_must_staple(certificate)):
                        self._error('ERROR: Certificate has OCSP Must-Staple but no OSCP staple found on ', host_desc, '\n', code=ErrorCode.VERIFY)

                if tlsa_records:
                    tlsa_match = False
                    for tlsa_record in tlsa_records:
                        if self._tlsa_record_matches(tlsa_record, installed_certificate, installed_chain, root_certificate):
                            self._info('TLSA record matches on ', host_desc, '\n', color='green')
                            self._detail('    ', tlsa_record, '\n')
                            tlsa_match = True
                        else:
                            self._detail('TLSA record does not match on ', host_desc, '\n')
                            self._detail('    ', tlsa_record, '\n')
                    if not tlsa_match:
                        self._error('ERROR: No TLSA records match ', key_type.upper(), ' certificate "',
                                    installed_certificate.get_subject().commonName, '" on ', host_desc, '\n', code=ErrorCode.VERIFY)

                if (protocol):
                    if ('public_key_pins' in (protocol_info or {})):
                        for pin_key_type, pin_key_name, pin_key_purpose, pin_key in keys:
                            digests = {'sha256': self._public_key_digest(pin_key, 'sha256'), 'sha512': self._public_key_digest(pin_key, 'sha512')}
                            for pin in protocol_info['public_key_pins']:
                                if (digests[pin[0]] == pin[1]):
                                    self._info('Public key pin found for ', pin_key_type.upper(), ' ', pin_key_purpose, ' key ', pin_key_name,
                                               ' on ', host_desc, '\n',
                                               color='green')
                                    break
                            else:
                                self._error('ERROR: Public key pin missing for ', pin_key_type.upper(), ' ', pin_key_purpose, ' key ', pin_key_name,
                                            ' on ', host_desc, '\n', code=ErrorCode.VERIFY)
                    else:
                        self._error('ERROR: Public key pins not found on ', host_desc, '\n', code=ErrorCode.VERIFY)

            except Exception as error:
                self._error('ERROR: Unable to connect to ', host_desc, ' via ', key_type.upper(), '\n', self._indent(error), '\n', code=ErrorCode.VERIFY)

    def verify_certificate_installation(self, private_key_names):
        key_type_ciphers = {}
        ssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD | OpenSSL.SSL.TLSv1_2_METHOD)
        ssl_sock = OpenSSL.SSL.Connection(ssl_context, socket.socket())
        all_ciphers = ssl_sock.get_cipher_list()
        key_type_ciphers['rsa'] = ':'.join([cipher_name for cipher_name in all_ciphers if 'RSA' in cipher_name]).encode('ascii')
        key_type_ciphers['ecdsa'] = ':'.join([cipher_name for cipher_name in all_ciphers if 'ECDSA' in cipher_name]).encode('ascii')

        root_certificates = self.load_root_certificates()

        private_keys = self._config('private_keys')
        for private_key_name in private_keys:
            if (private_key_names and (private_key_name not in private_key_names)):
                continue

            key_options = self._get_key_options(private_keys[private_key_name])
            if (not key_options):
                self._error('No configured private key types for ', private_key_name, '\n', code=ErrorCode.CONFIG)
                continue

            keys = []
            key_cipher_data = self.key_cipher_data(private_key_name)
            try:
                for key_type in key_options:
                    keys.append((key_type, private_key_name, 'private', self.load_private_key('private_key', private_key_name, key_type, key_cipher_data).key))
                    keys.append((key_type, private_key_name, 'backup', self.load_private_key('backup_key', private_key_name, key_type, key_cipher_data).key))
                    previous_key = self.load_private_key('previous_key', private_key_name, key_type, key_cipher_data).key
                    if (previous_key):
                        keys.append((key_type, private_key_name, 'previous', previous_key))
            except PrivateKeyError as error:
                self._error('Unable to load private key ', error, '\n', code=ErrorCode.KEY)
                continue

            key_certificates = private_keys[private_key_name].get('certificates', {})
            for certificate_name in key_certificates:
                verify_list = self._option_list(key_certificates[certificate_name], 'verify')
                if (verify_list):
                    alt_names = []
                    for zone_name in key_certificates[certificate_name]['alt_names']:
                        alt_names += self._get_domain_names(key_certificates[certificate_name]['alt_names'], zone_name)

                    certificate_key_types = self._get_list(key_certificates[certificate_name], 'key_types', key_options.keys())
                    for key_type in certificate_key_types:
                        certificate = self.load_certificate('certificate', certificate_name, key_type)
                        chain = self.load_chain(certificate_name, key_type)
                        if (not certificate):
                            self._error(key_type.upper(), ' certificate ', certificate_name, ' not found\n', code=ErrorCode.CONFIG)
                            continue

                        for verify in verify_list:
                            if (not verify.get('port')):
                                continue
                            if ('key_types' in verify):
                                if (key_type not in self._get_list(verify, 'key_types')):
                                    continue
                            for host_name in self._get_list(verify, 'hosts', alt_names):
                                if (self._host_in_list(host_name, alt_names)):
                                    self._verify_certificate_installation(certificate_name, certificate, chain, root_certificates[key_type], key_type,
                                                                          host_name, verify['port'], verify['starttls'], key_type_ciphers[key_type],
                                                                          verify['protocol'], keys)

    def show_config(self):
        self._info('Configuration:\n')
        self._status(json.dumps(self.config, indent=4), '\n')

    def _process_running(self, pid_file_path):
        try:
            with open(pid_file_path) as pid_file:
                return (-1 < os.getsid(int(pid_file.read())))
        except Exception:
            pass
        return False

    def run(self):
        self._validate_config()
        self._log('\n', self.script_name, ' executed at ', str(datetime.datetime.now()), '\n')
        if (self.args.show_config):
            self.show_config()
            return
        pid_file_path = os.path.join(self._directory('pid'), self.script_name + '.pid')
        if (self.args.random_wait):
            delay_seconds = min(random.randrange(min(self._setting_int('min_run_delay'), self._setting_int('max_run_delay')),
                                                 max(self._setting_int('min_run_delay'), self._setting_int('max_run_delay'))), 86400)

            def _plural(duration, unit):
                if (0 < duration):
                    return ('{duration} {unit}{plural} '.format(duration=duration, unit=unit, plural='' if (1 == duration) else 's'))
                return ''

            self._detail('Waiting for ',
                         _plural(int(delay_seconds / 3600), 'hour'), _plural(int((delay_seconds % 3600) / 60), 'minute'),
                         _plural((delay_seconds % 60), 'second'), '\n')
            time.sleep(delay_seconds)
            if (self._process_running(pid_file_path)):
                self._detail('Waiting for other running client instance\n')
                while (self._process_running(pid_file_path)):
                    time.sleep(random.randrange(5, 30))
        else:
            if (self._process_running(pid_file_path)):
                self._fatal('Client already running\n')
        with self._open_file(pid_file_path, mode='w') as pid_file:
            pid_file.write(str(os.getpid()))
        try:
            if (not (self.args.revoke or self.args.auth or self.args.certs or self.args.tlsa or self.args.sct or self.args.ocsp or self.args.verify
                     or self.args.register or self.args.export_client or self.args.show_config)):
                self.args.auth = True
                self.args.certs = True
                self.args.tlsa = True
                self.args.sct = True
                self.args.ocsp = True
                self.args.verify = True

            if (self.args.revoke or self.args.auth or self.args.certs or self.args.register or self.args.export_client):
                self.connect_client()

            if (self.args.revoke):
                if (not self.args.private_key_names):
                    self._fatal('Revocation must explicitly specify private key names\n')
                else:
                    self.revoke_certificates(self.args.private_key_names)
            if (self.args.auth and not self._setting('follower_mode')):
                self.process_authorizations(self.args.private_key_names)
            if (self.args.certs):
                self.process_certificates(self._setting('follower_mode'), self.args.private_key_names)
            if (self.args.tlsa):
                self.update_tlsa_records(self.args.private_key_names)
            if (self.args.sct):
                self.update_signed_certificate_timestamps(self.args.private_key_names)
            if (self.args.ocsp):
                self.update_ocsp_responses(self.args.private_key_names)
            if (self.reload_services() and self.args.verify):
                time.sleep(5)   # allow time for services to reload before verification
            if (self.args.verify):
                self.verify_certificate_installation(self.args.private_key_names)
            if (self.args.export_client):
                self.export_client_key()
            self.disconnect_client()
        finally:
            os.remove(pid_file_path)


def debug_hook(type, value, tb):
    if hasattr(sys, 'ps1') or not sys.stderr.isatty():
        # we are in interactive mode or we don't have a tty-like
        # device, so we call the default hook
        sys.__excepthook__(type, value, tb)
    else:
        import traceback
        import pdb
        # we are NOT in interactive mode, print the exception...
        traceback.print_exception(type, value, tb)
        print()
        # ...then start the debugger in post-mortem mode.
        pdb.pm()
