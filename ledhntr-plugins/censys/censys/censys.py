"""
Overview
========

Use this plugin to interact with the Censys API

"""
import copy
import json
import logging
import os
import re
import requests
from pprint import pformat
from datetime import datetime, timezone
import dateutil.parser
from time import time

# import ledhntr.helpers.dbclient as dbc
from ledhntr.data_classes import (
    Attribute,
    Entity,
    Relation,
    Thing,
)
from ledhntr.helpers import LEDConfigParser
from ledhntr.plugins.hntr import HNTRPlugin, APIConfig
from ledhntr.plugins.connector import ConnectorPlugin

from typing import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
    Union
)

class Censys(HNTRPlugin):
    """
    Censys

    """
    def __init__(
        self,
        config:LEDConfigParser,
        logger: Optional[object] = None,
    ) -> None:
        super().__init__(config)

        if not logger:
            self.logger: logging.Logger = logging.getLogger('ledhntr')
        _log = self.logger
        self.config = config
        # Figure out best way to keep running talley of API calls

        self.base_url = config.get(
            'options',
            'base_url',
            fallback = 'https://search.censys.io/api/',
        )

        self.key = config.get(
            'options',
            'key',
            fallback = 'key',
        )

        self.secret = config.get(
            'options',
            'secret',
            fallback = "secret",
        )

        self.auth = (self.key, self.secret)
        if self.auth == ('key', 'secret'):
            _log.warning("INVALID AUTHORIZATION PROVIDED!")
            self.auth = False

        self.ssl_verify = config.get(
            'options',
            'ssl_verify',
            fallback = True,
        )
        if self.ssl_verify.lower() == "false":
            self.ssl_verify = False
        elif self.ssl_verify.lower() == "true":
            self.ssl_verify = True
        if not self.ssl_verify:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.con_threshold = float(config.get(
            'options',
            'con_threshold',
            fallback = '1.0',
        ))

        self.freq_threshold = int(config.get(
            'options',
            'freq_threshold',
            fallback = '24',
        ))

        self.rate_limit = int(config.get(
            'options',
            'rate_limit',
            fallback = '3',
        ))

        self.shared_host_threshold = int(config.get(
            'options',
            'shared_host_threshold',
            fallback = '25',
        ))

        self.per_page = int(config.get(
            'options',
            'per_page',
            fallback = '100',
        ))

        self.max_pages = int(config.get(
            'options',
            'max_pages',
            fallback = '10',
        ))

        self._load_api_configs()

    def _load_api_configs(
        self,
    ):
        """Load API configs for this plugin
        """
        _log = self.logger
        self.api_confs = {}

        '''
        Notes about setting param_query_key
        '''

        # Which param carries the default queries?
        self.param_query_key = "q"
        '''
        headers = {
            'Accept': 'application/json',
            'User-Agent': 'LED-HNTR v0.1',
            # 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
        }
        '''
        headers = {
            'Accept': 'application/json',
        }

        # search
        c = APIConfig(
            endpoint = "search",
            uri = "v2/hosts/search",
            auth = self.auth,
            headers = headers,
            params = {
                "q": None,
                "per_page": self.per_page,
                "virtual_hosts": "EXCLUDE", # EXLUDE|INCLUDE|ONLY
                "cursor": None,
                "fields": None,
            },
            paginate = False,
            paginator = self.main_paginator,
            parser = self.parse_hosts_search,
            add_to_db = self.add_hunt, # This can probably be revisited
            simple_query_types = [], # This can probably be anything we want to
            # pivot on - but I'll leave it blank for now so as not to get
            # carried away
            param_query_key=self.param_query_key,
            frequency = self.freq_threshold,
            hunt_active = True, # Determines if this endpoint should be regularly polled
            hunt_name = "hosts_search_{query}", # Only applies if we're using this
            # to create an enrichment. Enrichments will be named this.
            hok_logic = self.hok_hosts,
        )
        self.api_confs[c.endpoint] = c
        # Legacy support
        c2 = copy.deepcopy(c)
        c2.endpoint = "hosts_search"
        self.api_confs[c2.endpoint] = c2

        # censys_certificates_hosts - v2/certificates/{fingerprint}/hosts
        c = APIConfig(
            endpoint = "cert_hosts",
            uri = "v2/certificates/{query}/hosts",
            auth = self.auth,
            headers = headers,
            params = {
                "cursor": None,
            },
            paginate = False,
            paginator = self.main_paginator,
            parser = self.parse_certificates_hosts,
            add_to_db = self.add_hunt, # This can probably be revisited
            simple_query_types = ['ssl'],
            param_query_key=self.param_query_key,
            frequency = self.freq_threshold,
            hunt_active = False,
            hunt_name = "cert_hosts_{query}",
            hok_logic = None,
        )
        self.api_confs[c.endpoint] = c
        # Legacy support
        c2 = copy.deepcopy(c)
        c2.endpoint = "certificates_hosts"
        self.api_confs[c2.endpoint] = c2

        # censys_certificate - v1/view/certificates/{query}
        c = APIConfig(
            endpoint = "view_cert",
            uri = "v1/view/certificates/{query}",
            auth = self.auth,
            headers = headers,
            params = {},
            parser = self.parse_view_cert,
            add_to_db = self.add_hunt, # This can probably be revisited
            simple_query_types = ['ssl'],
            param_query_key=self.param_query_key,
            frequency = self.freq_threshold,
            hunt_active = False,
            hunt_name = "view_cert_{query}",
            hok_logic = None,
        )
        self.api_confs[c.endpoint] = c
        # Legacy support
        c2 = copy.deepcopy(c)
        c2.endpoint = "certificate"
        self.api_confs[c2.endpoint] = c2

        # censys_host_details - v2/hosts/{query}
        c = APIConfig(
            endpoint = "host_details",
            uri = "v2/hosts/{query}",
            auth = self.auth,
            headers = headers,
            params = {
                "at_time": None, # RFC3339 Timestamp
            },
            parser = self.new_parse_hosts,
            add_to_db = self.add_hunt, # This can probably be revisited
            simple_query_types = ['ip'],
            param_query_key=self.param_query_key,
            frequency = self.freq_threshold,
            hunt_active = True,
            hunt_name = "host_details_{query}",
            hok_logic = None,
        )
        self.api_confs[c.endpoint] = c
        # Legacy support
        # c2 = copy.deepcopy(c)
        # c2.endpoint = "censys_host_details"
        # self.api_confs[c2.endpoint] = c2

    #################################################
    ### Data Parsing Functions
    #################################################
    def new_parse_hosts(
        self,
        raw: Dict = {},
        api_conf: Optional[APIConfig] = None,
        check_dates: Optional[List]=[],
    ):
        """Use the new parsing method to generate things
        :params raw: JSON response from API endpoint
        :params api_conf: APIConfig for this request (unused at the moment)
        :params check_dates: List of dates to check if this search has already
            been run. If a date matches this function will return a date.

        :returns: list of Things normally, or date or False if check_dates=True
        """
        _log = self.logger
        all_things = []
        data = raw['result']

        # @ check_dates logic
        if check_dates:
            seen_rule = {'jsonpath': 'last_updated_at', 'label': 'date-seen'}
            return self.check_dates_shortcut(check_dates, raw['result'], seen_rule)

        # @ Top Level Metadata
        test = self.process_parsing_rules(
            data,
            {'jsonpath': 'ip', 'label': 'ip-address'},
            single=True
        )
        #// _log.info(test)
        ipaddy = self.process_parsing_rules(
            data,
            {'jsonpath': 'ip', 'label': 'ip-address'},
            single=True
        )[0]
        ledsrc = self.process_parsing_rules(
            data,
            {'jsonpath': 'ip', 'label': 'ledsrc'},
            single=True
        )[0]
        last_updated = self.process_parsing_rules(
            data,
            {'jsonpath': 'last_updated_at', 'label': 'date-seen'},
            single=True
        )[0]
        tags = self.process_parsing_rules(
            data,
            {'jsonpath': 'labels[*]', 'label': 'tag'},
            single=True
        )


        parsing_rules = {
            'attributes': [
                {'jsonpath': 'ip', 'label': 'ip-address'},
                {'jsonpath': 'last_updated_at', 'label': 'last-seen'},
                {'jsonpath': 'labels[*]', 'label': 'tag'}
            ],
            'entities': [
                {'label': 'autonomous-system', 'has': [
                    {'jsonpath': 'autonomous_system.asn', 'label': 'as-number'},
                    {'jsonpath': 'autonomous_system.name', 'label': 'as-name'},
                    {'jsonpath': 'autonomous_system.bgp_prefix', 'label': 'cidr-range'},
                    {'jsonpath': 'autonomous_system.country_code', 'label': 'country-code'},
                    {'jsonpath': 'autonomous_system_updated_at', 'label': 'date-seen'},
                    ledsrc,
                ]},
                {'label': 'dns-record', 'multipath': "dns.records", 'has': [
                    {'jsonpath': '', 'key':True, 'label':'fqdn'},
                    {'jsonpath': '*.record_type', 'label': 'dns-type'},
                    {'jsonpath': '*.resolved_at', 'label': 'date-seen'},
                    Attribute(label="dns-value", value=ipaddy.value),
                    ledsrc,
                ]},
                {'label': 'dns-record', 'multipath': "dns.reverse_dns", 'has': [
                    {'jsonpath': 'names[*]', 'label':'fqdn'},
                    Attribute(label='dns-type', value="PTR"),
                    {'jsonpath': 'resolved_at', 'label': 'date-seen'},
                    Attribute(label="dns-value", value=ipaddy.value),
                    ledsrc,
                ]},
                {'label': 'geoloc', 'has': [
                    {'jsonpath': 'location.coordinates.latitude', 'label': 'latitude'},
                    {'jsonpath': 'location.cooredinates.longitude', 'label': 'longitude'},
                    {'jsonpath': 'location.city', 'label': 'city'},
                    {'jsonpath': 'location.country_code', 'label': 'country-code'},
                    {'jsonpath': 'location.country', 'label': 'country'},
                    {'jsonpath': 'location.postal_code', 'label': 'postal-code'},
                    {'jsonpath': 'location.province', 'label': 'province'},
                    {'jsonpath': 'location.timezone', 'label': 'timezone'},
                    {'jsonpath': 'location_updated_at', 'label': 'date-seen'},
                    ledsrc,
                ]},
                {'label': 'ip', 'has': [
                    {'jsonpath': 'autonomous_system.asn', 'label': 'as-number'},
                    {'jsonpath': 'autonomous_system.name', 'label': 'as-name'},
                    {'jsonpath': 'autonomous_system.bgp_prefix', 'label': 'cidr-range'},
                    {'jsonpath': 'autonomous_system.country_code', 'label': 'country-code'},
                    {'jsonpath': 'location.city', 'label': 'city'},
                    {'jsonpath': 'location.country_code', 'label': 'country-code'},
                    {'jsonpath': 'location.country', 'label': 'country'},
                    {'jsonpath': 'location.postal_code', 'label': 'postal-code'},
                    {'jsonpath': 'location.province', 'label': 'province'},
                    {'jsonpath': 'location.timezone', 'label': 'timezone'},
                    {'jsonpath': 'services[*].banner', 'label': 'banner'},
                    {'jsonpath': 'services[*].banner_hashes[*]', 'label': 'banner-hash'},
                    {'jsonpath': 'services[*].port', 'label': 'port'},
                    {'jsonpath': 'services[*].extended_service_name', 'label': 'service-name'},
                    ipaddy, #@key
                    *tags,
                    last_updated,
                    ledsrc,
                ]},
                {'label': 'os', 'has': [
                    {'jsonpath': 'operating_system.uniform_resource_identifier', 'label': 'uniform-resource-identifier'},
                    {'jsonpath': 'product', 'label': 'product'},
                    {'jsonpath': 'part', 'label': 'part'},
                    {'jsonpath': 'vendor', 'label': 'vendor'},
                    {'jsonpath': 'version', 'label': 'version'},
                    {'jsonpath': 'last_updated_at', 'label': 'date-seen'},
                    ledsrc,
                ]},
                {'label': 'network-service', 'multipath': "services[*]", 'has': [
                    #. top-level
                    {'jsonpath': 'banner', 'label': 'banner'},
                    {'jsonpath': 'banner_hashes[*]', 'label': 'banner-hash'},
                    {'jsonpath': 'certificate', 'label': 'fingerprint'},
                    {'jsonpath': 'extended_service_name', 'label': 'service-name'},
                    {'jsonpath': 'labels[*]', 'label': 'tag'},
                    {'jsonpath': 'observed_at', 'label': 'date-seen'},
                    ipaddy,
                    {'jsonpath': 'port', 'label': 'port'},
                    #. dns
                    {'jsonpath': 'dns.version', 'label': 'version'},
                    {'jsonpath': 'dns.server_type', 'label': 'dns-server-type'},
                    {'jsonpath': 'dns.answers[*].type', 'label': 'dns-type'},
                    {'jsonpath': 'dns.authorities[*].response', 'label': 'dns-authority'},
                    {'jsonpath': 'dns.questions[*].name', 'label': 'dns-query'},
                    {'jsonpath': 'dns.questions[*].response', 'label': 'dns-response'},
                    {'jsonpath': 'dns.r_code', 'label': 'dns-rcode'},
                    {'jsonpath': 'dns.resolves_correctly', 'label': 'dns-resolves-correctly'},
                    #. ftp
                    {'jsonpath': 'ftp.auth_ssl_response', 'label': 'auth-ssl-response'},
                    {'jsonpath': 'ftp.auth_tls_response', 'label': 'auth-tls-response'},
                    {'jsonpath': 'ftp.banner', 'label': 'banner'},
                    {'jsonpath': 'ftp.status_code', 'label': 'status-code'},
                    {'jsonpath': 'ftp.status_meaning', 'label': 'status-meaning'},
                    #. http
                    {'jsonpath': 'http.response.headers', 'keyval':True, 'label': 'http-header-pair'},
                    {'jsonpath': 'http.response.status_code', 'label': 'status-code'},
                    {'jsonpath': 'http.response.body_size', 'label': 'http-html-size'},
                    {'jsonpath': 'http.response.body', 'label': 'http-html'},
                    {'jsonpath': 'http.response.favicons[*].hashes[*]', 'label': 'http-favicon-hash'},
                    {'jsonpath': 'http.response.body_hashes[*]', 'label': 'http-html-hash'},
                    {'jsonpath': 'http.response.html_title', 'label': 'http-html-title'},
                    #. imap
                    {'jsonpath': 'imap.banner', 'label': 'banner'},
                    {'jsonpath': 'imap.start_tls', 'label': 'start-tls'},
                    #. jarm
                    {'jsonpath': 'jarm.fingerprint', 'label': 'jarm-fingerprint'},
                    {'jsonpath': 'jarm.cipher_and_version_fingerprint', 'label': 'jarm-cipher'},
                    {'jsonpath': 'jarm.tls_extensions_sha256', 'label': 'jarm-tls-ext'},
                    #. pop3
                    {'jsonpath': 'pop3.banner', 'label': 'banner'},
                    {'jsonpath': 'pop3.start_tls', 'label': 'start-tls'},
                    #. smtp
                    {'jsonpath': 'smtp.banner', 'label': 'banner'},
                    {'jsonpath': 'smtp.ehlo', 'label': 'ehlo'},
                    {'jsonpath': 'smtp.start_tls', 'label': 'start-tls'},
                    #. software
                    {'jsonpath': 'software[*].uniform_resource_identifier', 'label': 'uniform-resource-identifier'},
                    {'jsonpath': 'software[*].product', 'label': 'product'},
                    {'jsonpath': 'software[*].part', 'label': 'part'},
                    {'jsonpath': 'software[*].vendor', 'label': 'vendor'},
                    {'jsonpath': 'software[*].version', 'label': 'version'},
                    #.ssh
                    {'jsonpath': 'ssh.endpoint_id.raw', 'label': 'banner'},
                    {'jsonpath': 'ssh.kex_init_message.kex_algorithms[*]', 'label': 'kex-algorithm'},
                    {'jsonpath': 'ssh.kex_init_message.host_key_algorithms[*]', 'label': 'host-key-algorithm'},
                    {'jsonpath': 'ssh.kex_init_message.client_to_server_ciphers[*]', 'label': 'client-cipher'},
                    {'jsonpath': 'ssh.kex_init_message.server_to_client_ciphers[*]', 'label': 'server-cipher'},
                    {'jsonpath': 'ssh.kex_init_message.client_to_server_macs[*]', 'label': 'client-mac-algorithm'},
                    {'jsonpath': 'ssh.kex_init_message.server_to_client_macs[*]', 'label': 'server-mac-algorithm'},
                    {'jsonpath': 'ssh.kex_init_message.client_to_server_compression[*]', 'label': 'client-compression-algorithm'},
                    {'jsonpath': 'ssh.kex_init_message.server_to_client_compression[*]', 'label': 'server-compression-algorithm'},
                    {'jsonpath': 'ssh.server_host_key.fingerprint_sha256', 'label': 'fingerprint'},
                    {'jsonpath': 'ssh.server_host_key.rsa_public_key.length', 'label': 'pubkey-bits'},
                    {'jsonpath': 'ssh.hassh_fingerprint', 'label': 'hassh-fingerprint'},
                    #. ssl
                    {'jsonpath': 'tls.cipher_selected', 'label': 'cipher-name'},
                    {'jsonpath': 'tls.certificates.leaf_data.names[*]', 'label': 'fqdn'},
                    {'jsonpath': 'tls.certificates.leaf_data.pubkey_bit_size', 'label': 'pubkey-bits'},
                    {'jsonpath': 'tls.certificates.leaf_data.pubkey_algorithm', 'label': 'pubkey-type'},
                    {'jsonpath': 'tls.certificates.leaf_data.fingerprint', 'label': 'fingerprint'},
                    {'jsonpath': 'tls.certificates.leaf_data.issuer.common_name[*]', 'label': 'issuer-cn'},
                    {'jsonpath': 'tls.certificates.leaf_data.issuer.organization[*]', 'label': 'issuer-o'},
                    {'jsonpath': 'tls.certificates.leaf_data.issuer.country[*]', 'label': 'issuer-c'},
                    {'jsonpath': 'tls.certificates.leaf_data.issuer.locality[*]', 'label': 'issuer-l'},
                    {'jsonpath': 'tls.certificates.leaf_data.issuer.organizational_unit[*]', 'label': 'issuer-ou'},
                    {'jsonpath': 'tls.certificates.leaf_data.issuer.province[*]', 'label': 'issuer-st'},
                    {'jsonpath': 'tls.certificates.leaf_data.subject.common_name[*]', 'label': 'subject-cn'},
                    {'jsonpath': 'tls.certificates.leaf_data.subject.organization[*]', 'label': 'subject-o'},
                    {'jsonpath': 'tls.certificates.leaf_data.subject.country[*]', 'label': 'subject-c'},
                    {'jsonpath': 'tls.certificates.leaf_data.subject.locality[*]', 'label': 'subject-l'},
                    {'jsonpath': 'tls.certificates.leaf_data.subject.organizational_unit[*]', 'label': 'subject-ou'},
                    {'jsonpath': 'tls.certificates.leaf_data.subject.province[*]', 'label': 'subject-st'},
                    {'jsonpath': 'tls.certificates.leaf_data.signature.signature_algorithm', 'label': 'sig-alg'},
                    {'jsonpath': 'tls.certificates.leaf_data.chain[*].fingerprint', 'label': 'chain-fingerprint'},
                    {'jsonpath': 'tls.ja3s', 'label': 'ja3s'},
                    {'jsonpath': 'tls.ja4s', 'label': 'ja4s'},
                    {'jsonpath': 'tls.versions[*].tls_version', 'label': 'version'},
                    #. meta
                    ledsrc,
                ]},
                #@ Specific Service Entities
                {'label':'dns-service', 'multipath':'services[*]', 'has':[
                    {'jsonpath': 'dns.version', 'label': 'version'},
                    {'jsonpath': 'dns.server_type', 'label': 'dns-server-type'},
                    {'jsonpath': 'dns.answers[*].type', 'label': 'dns-type'},
                    {'jsonpath': 'dns.authorities[*].response', 'label': 'dns-authority'},
                    {'jsonpath': 'dns.questions[*].name', 'label': 'dns-query'},
                    {'jsonpath': 'dns.questions[*].response', 'label': 'dns-response'},
                    {'jsonpath': 'dns.r_code', 'label': 'dns-rcode'},
                    {'jsonpath': 'dns.resolves_correctly', 'label': 'dns-resolves-correctly'},
                    # ! Required Glue
                    {'jsonpath': 'observed_at', 'label': 'date-seen'},
                    ledsrc,
                ]},
                {'label':'ftp', 'multipath':'services[*]', 'has':[
                    {'jsonpath': 'ftp.auth_ssl_response', 'label': 'auth-ssl-response'},
                    {'jsonpath': 'ftp.auth_tls_response', 'label': 'auth-tls-response'},
                    {'jsonpath': 'ftp.banner', 'label': 'banner'},
                    {'jsonpath': 'ftp.status_code', 'label': 'status-code'},
                    {'jsonpath': 'ftp.status_meaning', 'label': 'status-meaning'},
                    # ! Required Glue
                    {'jsonpath': 'observed_at', 'label': 'date-seen'},
                    ledsrc,
                ]},
                {'label':'http', 'multipath':'services[*]', 'has':[
                    {'jsonpath': 'http.response.headers', 'keyval':True, 'label': 'http-header-pair'},
                    {'jsonpath': 'http.response.status_code', 'label': 'status-code'},
                    {'jsonpath': 'http.response.body_size', 'label': 'http-html-size'},
                    {'jsonpath': 'http.response.body', 'label': 'http-html'},
                    {'jsonpath': 'http.response.favicons[*].hashes[*]', 'label': 'http-favicon-hash'},
                    {'jsonpath': 'http.response.body_hashes[*]', 'label': 'http-html-hash'},
                    {'jsonpath': 'http.response.html_title', 'label': 'http-html-title'},
                    # ! Required Glue
                    {'jsonpath': 'observed_at', 'label': 'date-seen'},
                    ledsrc,
                ]},
                {'label':'imap', 'multipath':'services[*]', 'has':[
                    {'jsonpath': 'imap.banner', 'label': 'banner'},
                    {'jsonpath': 'imap.start_tls', 'label': 'start-tls'},
                    # ! Required Glue
                    {'jsonpath': 'observed_at', 'label': 'date-seen'},
                    ledsrc,
                ]},
                {'label':'jarm', 'multipath':'services[*]', 'has':[
                    {'jsonpath': 'jarm.fingerprint', 'label': 'fingerprint'}, #@key
                    {'jsonpath': 'jarm.fingerprint', 'label': 'jarm-fingerprint'},
                    {'jsonpath': 'jarm.cipher_and_version_fingerprint', 'label': 'jarm-cipher'},
                    {'jsonpath': 'jarm.tls_extensions_sha256', 'label': 'jarm-tls-ext'},
                    {'jsonpath': 'jarm.observed_at', 'label': 'date-seen'},
                    # ! Required Glue
                    {'jsonpath': 'observed_at', 'label': 'date-seen'},
                    ledsrc,
                ]},
                {'label':'pop3', 'multipath':'services[*]', 'has':[
                    {'jsonpath': 'pop3.banner', 'label': 'banner'},
                    {'jsonpath': 'pop3.start_tls', 'label': 'start-tls'},
                    # ! Required Glue
                    {'jsonpath': 'observed_at', 'label': 'date-seen'},
                    ledsrc,
                ]},
                {'label':'smtp', 'multipath':'services[*]', 'has':[
                    {'jsonpath': 'smtp.banner', 'label': 'banner'},
                    {'jsonpath': 'smtp.ehlo', 'label': 'ehlo'},
                    {'jsonpath': 'smtp.start_tls', 'label': 'start-tls'},
                    # ! Required Glue
                    {'jsonpath': 'observed_at', 'label': 'date-seen'},
                    ledsrc,
                ]},
                {'label':'software', 'multipath':'services[*]', 'has':[
                    {'jsonpath': 'software[*].uniform_resource_identifier', 'label': 'uniform-resource-identifier'},
                    {'jsonpath': 'software[*].product', 'label': 'product'},
                    {'jsonpath': 'software[*].part', 'label': 'part'},
                    {'jsonpath': 'software[*].vendor', 'label': 'vendor'},
                    {'jsonpath': 'software[*].version', 'label': 'version'},
                    # ! Required Glue
                    {'jsonpath': 'observed_at', 'label': 'date-seen'},
                    ledsrc,
                ]},
                {'label':'ssh', 'multipath':'services[*]', 'has':[
                    {'jsonpath': 'ssh.endpoint_id.raw', 'label': 'banner'},
                    {'jsonpath': 'ssh.kex_init_message.kex_algorithms[*]', 'label': 'kex-algorithm'},
                    {'jsonpath': 'ssh.kex_init_message.host_key_algorithms[*]', 'label': 'host-key-algorithm'},
                    {'jsonpath': 'ssh.kex_init_message.client_to_server_ciphers[*]', 'label': 'client-cipher'},
                    {'jsonpath': 'ssh.kex_init_message.server_to_client_ciphers[*]', 'label': 'server-cipher'},
                    {'jsonpath': 'ssh.kex_init_message.client_to_server_macs[*]', 'label': 'client-mac-algorithm'},
                    {'jsonpath': 'ssh.kex_init_message.server_to_client_macs[*]', 'label': 'server-mac-algorithm'},
                    {'jsonpath': 'ssh.kex_init_message.client_to_server_compression[*]', 'label': 'client-compression-algorithm'},
                    {'jsonpath': 'ssh.kex_init_message.server_to_client_compression[*]', 'label': 'server-compression-algorithm'},
                    {'jsonpath': 'ssh.server_host_key.fingerprint_sha256', 'label': 'fingerprint'}, #@key
                    {'jsonpath': 'ssh.server_host_key.rsa_public_key.length', 'label': 'pubkey-bits'},
                    {'jsonpath': 'ssh.hassh_fingerprint', 'label': 'hassh-fingerprint'},
                    # ! Required Glue
                    {'jsonpath': 'observed_at', 'label': 'date-seen'},
                    ledsrc,
                ]},
                {'label':'ssl', 'multipath':'services[*]', 'has':[
                    {'jsonpath': 'tls.cipher_selected', 'label': 'cipher-name'},
                    {'jsonpath': 'tls.certificates.leaf_data.names[*]', 'label': 'fqdn'},
                    {'jsonpath': 'tls.certificates.leaf_data.pubkey_bit_size', 'label': 'pubkey-bits'},
                    {'jsonpath': 'tls.certificates.leaf_data.pubkey_algorithm', 'label': 'pubkey-type'},
                    {'jsonpath': 'tls.certificates.leaf_data.fingerprint', 'label': 'fingerprint'}, #@key
                    {'jsonpath': 'tls.certificates.leaf_data.issuer.common_name[*]', 'label': 'issuer-cn'},
                    {'jsonpath': 'tls.certificates.leaf_data.issuer.organization[*]', 'label': 'issuer-o'},
                    {'jsonpath': 'tls.certificates.leaf_data.issuer.country[*]', 'label': 'issuer-c'},
                    {'jsonpath': 'tls.certificates.leaf_data.issuer.locality[*]', 'label': 'issuer-l'},
                    {'jsonpath': 'tls.certificates.leaf_data.issuer.organizational_unit[*]', 'label': 'issuer-ou'},
                    {'jsonpath': 'tls.certificates.leaf_data.issuer.province[*]', 'label': 'issuer-st'},
                    {'jsonpath': 'tls.certificates.leaf_data.subject.common_name[*]', 'label': 'subject-cn'},
                    {'jsonpath': 'tls.certificates.leaf_data.subject.organization[*]', 'label': 'subject-o'},
                    {'jsonpath': 'tls.certificates.leaf_data.subject.country[*]', 'label': 'subject-c'},
                    {'jsonpath': 'tls.certificates.leaf_data.subject.locality[*]', 'label': 'subject-l'},
                    {'jsonpath': 'tls.certificates.leaf_data.subject.organizational_unit[*]', 'label': 'subject-ou'},
                    {'jsonpath': 'tls.certificates.leaf_data.subject.province[*]', 'label': 'subject-st'},
                    {'jsonpath': 'tls.certificates.leaf_data.signature.signature_algorithm', 'label': 'sig-alg'},
                    {'jsonpath': 'tls.certificates.leaf_data.chain[*].fingerprint', 'label': 'chain-fingerprint'},
                    {'jsonpath': 'tls.ja3s', 'label': 'ja3s'},
                    {'jsonpath': 'tls.ja4s', 'label': 'ja4s'},
                    {'jsonpath': 'tls.versions[*].tls_version', 'label': 'version'},
                    # ! Required Glue
                    {'jsonpath': 'observed_at', 'label': 'date-seen'},
                    ledsrc,
                ]},
            ],
            'relations':[],
        }

        _log.debug(f"attr: {len(parsing_rules['attributes'])} ent: {len(parsing_rules['entities'])} rel: {len(parsing_rules['relations'])}")
        parsed_result = self.process_parsing_rules(data, parsing_rules)
        for _, things in parsed_result.items():
            for thing in things:
                if thing not in all_things:
                    all_things.append(thing)

        while None in all_things:
            all_things.remove(None)

        return all_things

        # TODO - remember the check_dates function
        # TODO - add metadata like date-seen
        # TODO - add the actual parsing function
        # TODO - verify new_parsing_rules

    def parse_hosts_search(
        self,
        raw: Dict = {},
        api_conf: Optional[APIConfig] = None,
        check_dates: Optional[List]=[],
    ):
        things = []
        response = raw # It's just easier to do this than find/replace
        _log = self.logger
        _log.info(f"Parsing /hosts/search/ results..")
        if 'result' not in response:
            if 'results' in response:
                r = response['results']
            else:
                _log.error(
                    f"No results to parse! "
                    f"Full results: \n{pformat(response)}"
                )
        else:
            r = response['result']
        ip_counter = 0
        if r['total'] > 0:
            date_seen = None
            last_updated = None
            for hit in r['hits']:
                # Setup max last-seen value for latest date-seen attribute on hunt
                data = hit
                if 'last_updated_at' in data:
                    data['last_updated_at'] = self._format_date(
                        data['last_updated_at']
                    )
                    if not date_seen or data['last_updated_at'] > date_seen:
                        date_seen = data['last_updated_at']
                        if check_dates:
                            if date_seen in check_dates:
                                return date_seen
                            else:
                                return False
                        last_updated = Attribute(label='date-seen', value=date_seen)

                ip_counter += 1
                datakey_attrlbls = {
                    'ip': 'ip-address',
                    'last_updated_at': 'date-seen',
                }
                has = []
                # Add DNS resolutions as notes
                if data.get('dns'):
                    dns_res = data.get('dns')
                    if dns_res.get('reverse_dns'):
                        rdns = dns_res.get('reverse_dns')
                        if rdns.get('names'):
                            dns_names = rdns.get('names')
                            for name in dns_names:
                                note = Attribute(label='note', value=name)
                                if note not in has:
                                    has.append(note)
                ent_ip = self._generate_entity_from_data(
                    data=data,
                    datakey_attrlbls=datakey_attrlbls,
                    label='ip',
                    has=has,
                )
                ent_ip = self.check_dateseen(ent_ip, last_updated)
                if ent_ip not in things:
                    things.append(ent_ip)

                if 'location' in hit:
                    data = hit['location']
                    datakey_attrlbls = {
                        'continent': 'continent',
                        'country': 'country',
                        'country_code': 'country-code',
                        'city': 'city',
                        'postal_code': 'postal-code',
                        'timezone': 'timezone',
                        'province': 'province',
                        'registered_country': 'registered-country',
                        'registered_country_code': 'registered-country-code',
                    }
                    has = []
                    rel = self._generate_relation_from_data(
                        data=data,
                        datakey_attrlbls=datakey_attrlbls,
                        label='geoloc',
                        has=has,
                        players = {'located-in': [ent_ip]}
                    )
                    # rel = self.check_dateseen(rel, last_updated)
                    if rel not in things:
                        things.append(rel)

                if 'autonomous_system' in hit:
                    data = hit['autonomous_system']
                    if 'asn' in data:
                        data['asn'] = str(data['asn'])
                    datakey_attrlbls = {
                        'asn': 'as-number',
                        'description': 'isp',
                        'name': 'as-name',
                        'country_code': 'country-code',
                    }
                    has = []
                    asn_rel = self._generate_relation_from_data(
                        data = data,
                        datakey_attrlbls=datakey_attrlbls,
                        label = 'autonomous-system',
                        has=has,
                        players = {'linked': [ent_ip]}
                    )
                    # If you figure out how to avoid the duplicate links, this
                    # will probably need to be removed and asn_rel will need to
                    # be added as a 'linked' player
                    # if asn_rel not in things:
                    #     things.append(asn_rel)
                    # Add CIDR
                    '''
                    datakey_attrlbls = {
                        'bgp_prefix': 'cidr-range',
                    }
                    cidr_rel = self._generate_relation_from_data(
                        data = data,
                        datakey_attrlbls=datakey_attrlbls,
                        label = 'cidr',
                        has = [],
                        players = {
                            'linked': [],
                            'contains': [ent_ip]
                        }
                    )
                    # only add asns if they have an as-number (keyattr)

                    for attr in asn_rel.has:
                        if attr.label=='as-number':
                            cidr_rel.players['linked'].append(asn_rel)
                            break
                    # cidr_rel = self.check_dateseen(cidr_rel, last_updated)
                    if cidr_rel not in things:
                        things.append(cidr_rel)
                    '''
            if last_updated and last_updated.value is not None:
                things.append(last_updated)
        while None in things:
            things.remove(None)
        _log.info(f"Parsed {len(things)} things from {ip_counter} IPs!")
        return things

    def parse_certificates_hosts(
        self,
        raw: Dict = {},
        api_conf: Optional[APIConfig] = None,
        check_dates: Optional[List]=[],
    ):
        _log = self.logger
        _log.info(f"Parsing certificiates host results!")
        things = []
        response = raw

        _log.info(f"Parsing certificate hosts...")
        # _log.info(f"results:\n {pformat(response)}")
        if not 'result' in response:
            _log.warning(f"No results found!")
            return things
        result = response['result']

        cert_host_res = {}

        if 'hosts' in result:
            date_seen = None
            last_updated = None
            for host in result['hosts']:
                data = host
                ip = data['ip']
                if ip not in cert_host_res:
                    cert_host_res[ip] = {
                        'ip-address': ip,
                        'fqdn': [],
                        'date-seen': [],
                    }
                if 'name' in data:
                    name = data['name']
                    if name not in cert_host_res[ip]['fqdn']:
                        cert_host_res[ip]['fqdn'].append(name)

                if 'first_observed_at' in data:
                    foa = data['first_observed_at']
                    if foa not in cert_host_res[ip]['date-seen']:
                        cert_host_res[ip]['date-seen'].append(foa)

                if 'observed_at' in data:
                    oa = data['observed_at']
                    dsts = self._format_date(data['observed_at'])
                    if not date_seen or dsts > date_seen:
                        date_seen = dsts
                        if check_dates:
                            if dsts in check_dates:
                                return dsts
                            else:
                                return False
                        last_updated = Attribute(label='date-seen', value=dsts)
                    if oa not in cert_host_res[ip]['date-seen']:
                        cert_host_res[ip]['date-seen'].append(oa)

        for ip, info in cert_host_res.items():
            data = info
            dka = {
                'ip-address': 'ip-address',
                'fqdn': 'fqdn',
                'date-seen': 'date-seen',
            }
            has = []
            ent_cert_host = self._generate_entity_from_data(
                    data=data,
                    datakey_attrlbls=dka,
                    label='cert-host',
                    has=has,
                )
            ent_cert_host = self.check_dateseen(ent_cert_host, last_updated)
            things.append(ent_cert_host)

        if last_updated and last_updated.value is not None:
            things.append(last_updated)
        while None in things:
            things.remove(None)
        return things

    def parse_hosts(
        self,
        raw: Dict = {},
        api_conf: Optional[APIConfig] = None,
        check_dates: Optional[List]=[],
    ):
        _log = self.logger

        things = []
        response = raw

        _log.info(f"Parsing hosts...")
        # _log.info(f"results:\n {pformat(response)}")
        if not 'result' in response:
            _log.warning(f"No results found!")
            return things
        result = response['result']

        last_updated = None
        if 'last_updated_at' in result:
            val = self._format_date(result['last_updated_at'])
            if val is not None:
                if check_dates:
                    if val in check_dates:
                        return val
                    else:
                        return False
                last_updated = Attribute(label='date-seen', value=val)
                things.append(last_updated)
                # things.append(Attribute(label='note', value=f"last_updated:{val}"))
            else:
                if check_dates:
                    return False
        this_ip = None
        if 'ip' in result:
            host_ip = Attribute(label='note', value=result['ip'])
            this_ip = Attribute(label='ip-address', value=result['ip'])
            data = {
                'ip': result['ip'],
            }
            datakey_attrlbls = {
                'ip': 'ip-address',
            }
            has = [last_updated]
            ent_ip = self._generate_entity_from_data(
                data=data,
                datakey_attrlbls=datakey_attrlbls,
                label="ip",
                has=has,
            )
            # things['Entites'].append(ent_ip)
            ent_ip = self.check_dateseen(ent_ip, last_updated)

            # Add the IP LAST because we might want to tag it as other things
            # are processing (like DNS resolutions)
            # if ent_ip:
            #     things.append(ent_ip)

        if 'location' in result:
            if 'location_updated_at' in result:
                val = self._format_date(result['location_updated_at'])
                loc_updated = Attribute(label='date-seen', value=val)
                # things['Attributes'].append(loc_updated)
                # things.append(loc_updated)
            data = result['location']
            datakey_attrlbls = {
                'continent': 'continent',
                'country': 'country',
                'country_code': 'country-code',
                'city': 'city',
                'postal_code': 'postal-code',
                'timezone': 'timezone',
                'province': 'province',
                'registered_country': 'registered-country',
                'registered_country_code': 'registered-country-code',
            }
            has = [loc_updated]
            rel = self._generate_relation_from_data(
                data=data,
                datakey_attrlbls=datakey_attrlbls,
                label='geoloc',
                has=has,
                players = {'located-in': [ent_ip]}
            )
            # things['Relations'].append(rel)
            if rel:
                things.append(rel)

        if 'autonomous_system' in result:
            if 'autonomous_system_updated_at' in result:
                val = self._format_date(result['autonomous_system_updated_at'])
                asn_updated = Attribute(
                    label='date-seen',
                    value=val,
                )
            data = result['autonomous_system']
            if 'asn' in data:
                data['asn'] = str(data['asn'])
            datakey_attrlbls = {
                'asn': 'as-number',
                'description': 'isp',
                'name': 'as-name',
                'country_code': 'country-code',
            }
            has = [asn_updated]
            asn_rel = self._generate_relation_from_data(
                data = data,
                datakey_attrlbls=datakey_attrlbls,
                label = 'autonomous-system',
                has=has,
                players = {'linked': [ent_ip]}
            )
            # Add CIDR
            '''
            datakey_attrlbls = {
                'bgp_prefix': 'cidr-range',
            }
            cidr_rel = self._generate_relation_from_data(
                data = data,
                datakey_attrlbls=datakey_attrlbls,
                label = 'cidr',
                has = [],
                players = {
                    'linked': [],
                    'contains': [ent_ip]
                }
            )
            for attr in asn_rel.has:
                if attr.label=='as-number':
                    cidr_rel.players['linked'].append(asn_rel)
                    break
            if cidr_rel not in things:
                things.append(cidr_rel)
            '''

        if 'operating_system' in result:
            data = result['operating_system']
            datakey_attrlbls = {
                'uniform_resource_identifier': 'uniform-resource-identifier',
                'part': 'part',
                'vendor': 'vendor',
                'product': 'product',
                'version': 'version',
            }
            has = [last_updated]
            ent = self._generate_entity_from_data(
                data=data,
                datakey_attrlbls=datakey_attrlbls,
                label="os",
                has=has,
            )
            things.append(ent)

        shared_host = False
        if 'dns' in result:
            data = result['dns']
            if 'records' in data:
                if len(data['records']) > self.shared_host_threshold:
                    _log.info(f"Potential shared-host detected!")
                    _log.info(f"{this_ip.value} hosts {len(data['records'])} domains!")
                    shared_host = Attribute(label='tag', value='shared-host')
                    if ent_ip and shared_host not in ent_ip.has:
                        ent_ip.has.append(shared_host)
                    if shared_host not in things:
                        things.append(shared_host)
                if not shared_host:
                    for query, v in data['records'].items():
                        dns_type = Attribute(label='note', value=f"dns-type:{v['record_type']}")
                        dateval = self._format_date(v['resolved_at'])
                        resolved_at = Attribute(label='date-seen', value=dateval)
                        fqdn = Attribute(label='fqdn', value=query)
                        hostname = Entity(label='hostname', has=[fqdn, resolved_at])
                        '''
                        dns_record = Entity(
                            label="dns-record",
                            has = [dns_type, resolved_at, fqdn]
                        )
                        '''
                        resolution = Relation(
                            label="resolution",
                            has=[dns_type, fqdn, resolved_at, this_ip],
                            players = {
                                # 'query': [dns_record],
                                # 'answer': [ent_ip],
                                'resolves': [ent_ip, hostname]
                            }
                        )
                        resolution = self.check_dateseen(resolution, last_updated)
                        if resolution not in things:
                            things.append(resolution)
            if 'reverse_dns' in data:
                for name in data['reverse_dns']['names']:
                    dns_type = Attribute(label='dns-type', value='PTR')
                    if data['reverse_dns']['resolved_at']:
                        dateval = self._format_date(data['reverse_dns']['resolved_at'])
                        resolved_at = Attribute(
                            label='date-seen',
                            value=dateval
                        )
                    else:
                        resolved_at = None
                    fqdn = Attribute(label='fqdn', value=name)
                    hostname = Entity(label='hostname', has=[fqdn, resolved_at])
                    '''
                    dns_record = Entity(
                        label="dns-record",
                        has = [dns_type, resolved_at, fqdn]
                    )
                    '''
                    resolution = Relation(
                        label='resolution',
                        has=[dns_type, fqdn, resolved_at, this_ip],
                        players = {
                            # 'query': [ent_ip],
                            # 'answer': [dns_record],
                            'resolves': [ent_ip, hostname]
                        }
                    )
                    resolution = self.check_dateseen(resolution, last_updated)
                    things.append(resolution)

        #######################################################################
        #### Process Services
        #### There are... so... so many....
        #### https://search.censys.io/search/definitions?resource=hosts
        #### Let's start with a few and go from there...
        #######################################################################
        if not 'services' in result or not result['services']:
            now = datetime.now().astimezone(timezone.utc)
            empty_res_date = now.strftime("%Y-%m-%dT%H:%M:%S")
            empty_note = Attribute(
                label='note',
                value=f"empty-result:{empty_res_date}"
            )
            things.append(empty_note)
        for service in result['services']:
            provider = Attribute(label='service-provider', value=str(self.__class__.__name__))
            dateval = self._format_date(service['observed_at'])
            seen = Attribute(label='date-seen', value=dateval)
            if 'source_ip' in service:
                benign_ip = Attribute(label='ip-address', value=service['source_ip'])
                tag = Attribute(label='tag', value='censys-scanner')
                confidence = Attribute(label='confidence', value=-1.0)
                benign_ip_ent = Entity(
                    label='ip',
                    has = [benign_ip, tag, seen]
                )
                cons = benign_ip_ent.get_attributes('confidence')
                if cons is not None:
                    for con in cons:
                        benign_ip_ent.has.remove(con)
                benign_ip_ent.has.append(confidence)
                benign_ip_ent = self.check_dateseen(benign_ip_ent, seen)
                things.append(benign_ip_ent)
            data = service
            # basics
            datakey_attrlbls = {
                'banner': 'service-header',
                'observed_at': 'date-seen',
                'port': 'port',
                'service_name': 'service-name',
            }
            has = [provider, host_ip, seen]
            # has = [provider]
            service_rel = self._generate_relation_from_data(
                data=data,
                datakey_attrlbls=datakey_attrlbls,
                label='network-service',
                has=has,
                players = {
                    'running-on': [ent_ip],
                    'serves': [],
                    'related': [],
                }
            )
            # software
            if 'software' in service:
                # running=False
                for software_data in service['software']:
                    software_dka = {
                        'product': 'product',
                        'uniform_resource_identifier': 'uniform-resource-identifier',
                        'part': 'part',
                        'vendor': 'vendor',
                        'product': 'product',
                        'version': 'version',
                    }
                    has = [seen]
                    ent = self._generate_entity_from_data(
                        data = software_data,
                        datakey_attrlbls=software_dka,
                        label='software',
                        has=has,
                    )
                    service_rel.players['serves'].append(ent)

            # ssh
            if 'ssh' in service:
                ssh_data = service['ssh']
                ssh_dka = {}
                if 'server_host_key' in ssh_data:
                    if 'fingerprint_sha256' in ssh_data['server_host_key']:
                        attr = Attribute(
                            label='fingerprint',
                            value=ssh_data['server_host_key']['fingerprint_sha256']
                        )
                        service_rel.has.append(attr)

            # http
            if 'http' in service:
                http_data = service['http']
                if 'supports_http2' in http_data:
                    attr = Attribute(
                        label='tag',
                        value = f"supports_http2:{http_data['supports_http2']}"
                    )
                    service_rel.has.append(attr)
                if 'response' in http_data:
                    response_data = http_data['response']
                    response_dka = {
                        'protocol': 'http-protocol',
                        'status_code': 'status-code',
                        'body_size': 'http-html-size',
                        # 'body': 'http-html', # Commenting out because of string limits
                        'body_hash': 'http-html-hash',
                        'html_title': 'http-title',
                    }
                    has = [seen]
                    response_ent = self._generate_entity_from_data(
                        data = response_data,
                        datakey_attrlbls=response_dka,
                        label='http',
                        has=has,
                    )
                    if 'headers' in response_data:
                        for headerkey, headervals in response_data['headers'].items():
                            if headerkey.startswith("_"):
                                continue
                            for val in headervals:
                                if val == "<REDACTED>":
                                    continue
                                if self._isa_date(val):
                                    continue
                                keyval = f"{headerkey}: {val}"
                                attr = Attribute(label="http-header-pair", value=keyval)
                                if attr not in response_ent.has:
                                    response_ent.has.append(attr)
                    service_rel.players['serves'].append(response_ent)

            # JARM
            if 'jarm' in service:
                jarm_data = service['jarm']
                jarm_dka = {
                    'fingerprint': 'fingerprint',
                    'cipher_and_version_fingerprint': 'jarm-cipher',
                    'tls_extensions_sha256': 'jarm-tls-ext',
                }
                if 'observed_at' in jarm_data:
                    dateval = self._format_date(jarm_data['observed_at'])
                    jarm_observed = Attribute(label='date-seen', value=dateval)
                else:
                    jarm_observed = None
                has = [jarm_observed]
                jarm_ent = self._generate_entity_from_data(
                    data = jarm_data,
                    datakey_attrlbls=jarm_dka,
                    label='jarm',
                    has=has,
                )
                service_rel.players['serves'].append(jarm_ent)
            # TLS
            if 'tls' in service:
                tls_data = service['tls']
                # tls_dka = {}
                # has = []
                if 'certificates' in tls_data:
                    cert_data = tls_data['certificates']
                    if 'leaf_data' in cert_data:
                        leaf_data = cert_data['leaf_data']
                        leaf_dka = {
                            'pubkey_bit_size': 'pubkey-bits',
                            'pubkey_algorithm': 'pubkey-type',
                            'fingerprint': 'fingerprint',
                        }
                        leaf_has = [seen]
                        if 'tbs_fingerprint' in leaf_data:
                            tbs = Attribute(
                                label='note',
                                value = f"tbs_fingerprint:{leaf_data['tbs_fingerprint']}"
                            )
                            leaf_has.append(tbs)
                        if 'names' in leaf_data:
                            for name in leaf_data['names']:
                                san = Attribute(label='fqdn', value=name)
                                leaf_has.append(san)
                                service_rel.has.append(san)
                                hostname = Entity(label='hostname', has=[san, seen])
                                things.append(hostname)
                        if 'issuer' in leaf_data:
                            for prop, vals in leaf_data['issuer'].items():
                                for val in vals:
                                    if prop=='common_name':
                                        attr = Attribute(
                                            label='issuer-cn', value=val
                                        )
                                        leaf_has.append(attr)
                                    elif prop=='locality':
                                        attr = Attribute(
                                            label='issuer-l', value=val
                                        )
                                        leaf_has.append(attr)
                                    elif prop=='organization':
                                        attr = Attribute(
                                            label='issuer-o', value=val
                                        )
                                        leaf_has.append(attr)
                                    elif prop=='country':
                                        attr = Attribute(
                                            label='issuer-c', value=val
                                        )
                                        leaf_has.append(attr)
                                    elif prop=='province':
                                        attr = Attribute(
                                            label='issuer-st', value=val
                                        )
                                        leaf_has.append(attr)
                                    elif prop=='organizational_unit':
                                        attr = Attribute(
                                            label='issuer-ou', value=val
                                        )
                                        leaf_has.append(attr)
                        if 'subject' in leaf_data:
                            for prop, vals in leaf_data['subject'].items():
                                for val in vals:
                                    if prop=='common_name':
                                        attr = Attribute(
                                            label='subject-cn', value=val
                                        )
                                        leaf_has.append(attr)
                                    elif prop=='locality':
                                        attr = Attribute(
                                            label='subject-l', value=val
                                        )
                                        leaf_has.append(attr)
                                    elif prop=='organization':
                                        attr = Attribute(
                                            label='subject-o', value=val
                                        )
                                        leaf_has.append(attr)
                                    elif prop=='country':
                                        attr = Attribute(
                                            label='subject-c', value=val
                                        )
                                        leaf_has.append(attr)
                                    elif prop=='province':
                                        attr = Attribute(
                                            label='subject-st', value=val
                                        )
                                        leaf_has.append(attr)
                                    elif prop=='organizational_unit':
                                        attr = Attribute(
                                            label='subject-ou', value=val
                                        )
                                        leaf_has.append(attr)
                        if 'signature' in leaf_data:
                            attr = Attribute(
                                label='sig-alg',
                                value=leaf_data['signature']['signature_algorithm']
                            )
                            leaf_has.append(attr)
                            if 'self_signed' in leaf_data['signature']:
                                tag = Attribute(
                                    label='tag',
                                    value=f"self-signed:{leaf_data['signature']['self_signed']}"
                                )
                                leaf_has.append(tag)

                if 'ja3s' in tls_data:
                    # tls_data['ja3s']
                    attr = Attribute(label='ja3s', value=tls_data['ja3s'])
                    leaf_has.append(attr)
                if 'version_selected' in tls_data:
                    attr = Attribute(label='version', value=tls_data['version_selected'])
                    leaf_has.append(attr)
                cert_ent = self._generate_entity_from_data(
                            data = leaf_data,
                            datakey_attrlbls=leaf_dka,
                            label='ssl',
                            has = leaf_has,
                        )
                service_rel.players['serves'].append(cert_ent)

            # FTP
            if 'ftp' in service:
                ftp_data = service['ftp']
                ftp_dka = {
                    'auth_tls_response': 'auth-tls-response',
                    'auth_ssl_response': 'auth-ssl-response',
                    'status_code': 'status-code',
                    'status_meaning': 'status-meaning',
                }
                has = [seen]
                if 'implicit_tls' in ftp_data:
                    attr = Attribute(label='tag', value=f"implicit_tls:{ftp_data['implicit_tls']}")
                    has.append(attr)
                ftp_ent = self._generate_entity_from_data(
                    data = ftp_data,
                    datakey_attrlbls=ftp_dka,
                    label='ftp',
                    has=has,
                )
                service_rel.players['serves'].append(ftp_ent)

            # DNS
            if 'dns' in service:
                dns_data = service['dns']
                has = [seen]
                '''
                if 'server_type' in dns_data:
                    attr = Attribute(
                        label='dns-server-type',
                        value=dns_data['server_type']
                    )
                    has.append(attr)
                '''
                if 'resolves_correctly' in dns_data:
                    attr = Attribute(
                        label='tag',
                        value=f"dns_resolves_correctly:{dns_data['resolves_correctly']}"
                    )
                    service_rel.has.append(attr)
                if 'r_code' in dns_data:
                    attr = Attribute(
                        label='tag',
                        value=f"dns_r_code:{dns_data['r_code']}"
                    )
                    service_rel.has.append(attr)
                if 'answers' in dns_data:
                    # dns_running = False
                    for answer in dns_data['answers']:
                        dns_query = Attribute(label='fqdn', value=answer['name'])
                        service_rel.has.append(dns_query)
                        hostname = Entity(label='hostname', has=[dns_query, seen])
                        things.append(hostname)
                        dns_type = Attribute(label='dns-type', value=answer['type'])
                        dns_response = Attribute(label='ip-address', value=answer['response'])
                        has += [dns_query, dns_type, dns_response]
                        relation_rel = Relation(
                            label='resolution',
                            has = has,
                        )
                        service_rel.players['related'].append(relation_rel)


            # SMTP/POP3/IMAP - start_tls
            #     smtp - ehlo
            if 'smtp' in service:
                smtp_data = service['smtp']
                if 'ehlo' in smtp_data:
                    attr = Attribute(label='note', value=f"smtp.ehlo:{smtp_data['ehlo']}")
                    # service_ent.has.append(attr)
                    service_rel.has.append(attr)
                if 'start_tls' in smtp_data:
                    attr = Attribute(label='note', value=f"smtp.start_tls:{smtp_data['start_tls']}")
                    service_rel.has.append(attr)
            if 'pop3' in service:
                smtp_data = service['pop3']
                if 'start_tls' in smtp_data:
                    attr = Attribute(label='note', value=f"pop3.start_tls:{smtp_data['start_tls']}")
                    service_rel.has.append(attr)
            if 'imap' in service:
                smtp_data = service['imap']
                if 'start_tls' in smtp_data:
                    attr = Attribute(label='note', value=f"imap.start_tls:{smtp_data['start_tls']}")
                    service_rel.has.append(attr)

            things.append(service_rel)

        # We add the IP last so we can potentially tag it with info that was
        # processed during parsing
        if ent_ip:
            things.append(ent_ip)

        while None in things:
            things.remove(None)

        # If this is likely a shared host, remove all 'resolutions'
        if shared_host:
            safe_things = copy.deepcopy(things)
            for st in safe_things:
                if st.label=='resolution':
                    things.remove(st)

        # Deduplicate
        dedup_things = []
        for thing in things:
            if thing not in dedup_things:
                dedup_things.append(thing)
                continue
            _log.info(f"Found duplicate things - merging!")
            first_thing = dedup_things.pop(dedup_things.index(thing))
            second_thing = thing
            merged_thing = first_thing.merge(**second_thing)
            _log.debug(f"first_thing: {first_thing}")
            _log.debug(f"second_thing: {second_thing}")
            _log.debug(f"merged result: {merged_thing}\n\t{pformat(merged_thing.to_dict())}")
            dedup_things.append(merged_thing)

        return dedup_things

    #### TODO

    def parse_historic_host(
        self,
        raw: Dict = {},
        api_conf: Optional[APIConfig] = None,
        check_dates: Optional[List]=[],
    ):
        # TODO
        _log = self.logger
        _log.info(f"Parsing historic results for host")
        things = []
        while None in things:
            things.remove(None)
        return things

    def parse_view_cert(
        self,
        raw: Dict = {},
        api_conf: Optional[APIConfig] = None,
        check_dates: Optional[List]=[],
    ):
        # TODO
        _log = self.logger
        _log.info(f"Parsing certificate!")
        things = []

        while None in things:
            things.remove(None)
        return things

    #################################################
    ### Pagination Functions
    #################################################

    def main_paginator(
        self,
        search_res: dict = {},
        api_conf: APIConfig = None,
    ):
        """Handles pagination in the event that's something we want

        Basically, if the 'page' parameter is set, we're going to assume
        we want to paginate through everything until we hit the self.max_pages
        limit.

        :param search_res: a dictionary containing raw results + parsed things
            from previous pages. This will get fed by HNTRPlugin.search()
        :param api_conf: APIConfig file of the endpoint we're hitting. This
            will be used to keep track of how many pages we've hit.
        :returns: updated search_res dictionary
        """
        _log = self.logger
        # * Add the last result to our 'raw_pages' collection
        search_res['raw_pages'].append(search_res['raw'])
        # * if the api_conf.paginate isn't set, we're not going to
        # * paginate the results, just return the first set like normal.
        if not api_conf.paginate:
            return search_res

        # * If we've gone past our max_pages count, stop collecting
        # _log.info(f"CURRENT PAGE_COUNT: {api_conf.page_count}")
        if api_conf.page_count >= self.max_pages:
            return search_res

        # * Calculate how many pages we need to get all the results
        total_results = search_res['raw']['result']['total']
        f_val = total_results/self.per_page
        pages_needed = int(f_val) + (1 if f_val - int(f_val) > 0 else 0)
        if pages_needed <= self.max_pages:
            x = f"{pages_needed} pages TOTAL."
        else:
            x = f"{self.max_pages} pages allowed by the max_pages config."

        current_page = api_conf.page_count
        if current_page >= pages_needed:
            return search_res

        cursor = search_res['raw']['result']['links'].get('next')
        if not cursor:
            return search_res

        # @ If you've made it this far, we still have pages to request.
        # @ Advance the counters and let 'er rip.
        next_page = int(current_page)+1
        api_conf.params['cursor']=cursor
        api_conf.page_count += 1
        # _log.info(f"NEW PAGE COUNT: {api_conf.page_count}")

        safe_copy = copy.deepcopy(search_res)
        _log.info(f"Searching page {next_page} of {x}")
        search_res = self.search(api_conf, search_res=search_res)
        return search_res

    #################################################
    ### Make Splunking Happy
    #################################################

    def chunk_results(
        self,
        raw: dict = {},
        api_conf: Optional[APIConfig] = None,
    ):
        """ Given raw results, break them up in happy little chunks

        :param raw: Raw JSON output in dict format returned from endpoint
        :param api_conf: APIConfig for determining how to handle processing
        :returns: List of bite-sized dictionaries
        """
        _log = self.logger
        chunks = []
        if not isinstance(raw, list):
            raw = [raw]

        if api_conf.endpoint=='search':
            counter = 1
            for r in raw:
                chunk = {
                    'total': r['result']['total'],
                    'result': 0,
                    'plugin': 'censys',
                    'endpoint': api_conf.endpoint,
                    'query': api_conf.params.get(api_conf.param_query_key),
                    'chunking_time': int(time()),
                    'hit': None,
                }
                for hit in r['result']['hits']:
                    new_chunk = copy.deepcopy(chunk)
                    new_chunk['result'] = counter
                    new_chunk['chunking_time'] = int(time())
                    new_chunk['hit'] = hit
                    chunks.append(new_chunk)
                    counter += 1

        return chunks

    #################################################
    ### hunt or Kill Logical Functions
    #################################################

    def hok_hosts(
        self,
        thing: Relation = None,
    ):
        """hunt-or-kill host enrichment logic

        **hunt-or-kill trigger logic**:
            - Associated IP has `shared-host` tag
            - Associated IP once had `network-services` players BUT has not seen
                them in 7+ days

        :param thing: The enrichment we're determining to hunt or kill
        :returns: True if HOK-logic was triggered, otherwise False.
        """
        _log = self.logger
        return False
