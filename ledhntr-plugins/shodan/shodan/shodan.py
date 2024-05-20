"""
Overview
========

Use this plugin to interact with the Shodan API

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
    Thing
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

class Shodan(HNTRPlugin):
    """
    Shodan

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
        self.base_url = config.get(
            'options',
            'base_url',
            fallback = 'https://api.shodan.io/',
        )

        self.key = config.get(
            'options',
            'key',
            fallback = 'key',
        )

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

        self.results_per_page = int(config.get(
            'options',
            'results_per_page',
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

        self.param_query_key = "query"

        headers = {
            "Accept": "application/json",
        }

        # shodan_hosts_search - shodan/host/search - parse_hosts_search
        c = APIConfig(
            endpoint = "hosts_search",
            uri = "shodan/host/search",
            auth = None,
            headers = headers,
            params = {
                "key": self.key,
                "query": None,
                "facets": None,
                "page": None,
                "minify": False,
            },
            paginate = False,
            paginator = self.main_paginator,
            parser = self.parse_hosts_search,
            add_to_db = self.add_hunt, # This can probably be revisited
            simple_query_types = [],
            param_query_key=self.param_query_key,
            frequency = self.freq_threshold,
            hunt_active = True, # Determines if this endpoint should be regularaly polled
            hunt_name = "hosts_search_{query}",
            hok_logic = None,
        )
        self.api_confs[c.endpoint] = c
        # Legacy support
        # c2 = copy.deepcopy(c)
        # c2.endpoint = "shodan_hosts_search"
        # self.api_confs[c2.endpoint] = c2

        # shodan_host_details - shodan/host/{query} - parse_hosts
        c = APIConfig(
            endpoint = "host_details",
            uri = "shodan/host/{query}",
            auth = None,
            headers = headers,
            params = {
                "key": self.key,
                "history": False,
                "minify": False,
            },
            parser = self.parse_hosts,
            add_to_db = self.add_hunt, # This can probably be revisited
            simple_query_types = ['ip'],
            param_query_key=self.param_query_key,
            frequency = self.freq_threshold,
            hunt_active = True,
            hunt_name = "hosts_search_{query}",
            hok_logic = None,
        )
        self.api_confs[c.endpoint] = c
        # Legacy support
        # c2 = copy.deepcopy(c)
        # c2.endpoint = "shodan_host_details"
        # self.api_confs[c2.endpoint] = c2

    #################################################
    ### Non-Standard Shodan API Functions
    #################################################

    def add_historical(
        self,
        dbc: ConnectorPlugin = None,
        ip: str = '',
        first_seen: Optional[Union[datetime, str]] = None,
        last_seen: Optional[Union[datetime, str]] = None,
        cached_data: Optional[object] =  None,
        force: Optional[bool] = False,
        hunt: Optional[Entity] = None,
    ):
        """
        Use this function to add historical data for a given IP.

        :param dbc: a database connector plugin used for writing objects to a db
        :param ip: The IP you wish to return historical data for
        :param first_seen: The earliest time you want to collect data from
        :param last_seen: The latest time you want to colelct data from

        """
        _log = self.logger

        # Find IP in database and get associated thing -
        # if doesn't exist, create it
        ip_attr = Attribute(label='ip-address', value=ip)
        search_ent = Entity(label='ip', has=[ip_attr])
        ip_ent = dbc.find_things(search_ent, limit_get=True)

        if not ip_ent:
            ip_ent = dbc.add_thing(search_ent, return_things=True)
        else:
            ip_ent=ip_ent[0]

        # Run historical search
        endpoint = "shodan_historic_host_details"
        if not first_seen:
            first_seen = datetime.fromtimestamp(0)
            first_seen = first_seen.replace(tzinfo=timezone.utc)
        else:
            first_seen = self._format_date(first_seen)
        if not last_seen:
            last_seen = datetime.now(timezone.utc)
        else:
            last_seen = self._format_date(last_seen)

        query_params = {
            'first_seen': first_seen,
            'last_seen': last_seen,
        }

        # Parse data with first_seen/last_seen ranges taken into account
        search_res = self.search(
            query = ip,
            endpoint = endpoint,
            cached_data = cached_data,
            hunt = hunt,
            **query_params
        )

        # Debug break
        # return search_res

        # Add disabled hunt object
        has = [
            Attribute(label='hunt-active', value=False),
            Attribute(label='hunt-service', value=self.__class__.__name__),
            Attribute(label='hunt-string', value=ip),
            Attribute(label='hunt-endpoint', value=endpoint),
            Attribute(label='frequency', value=24),
            Attribute(label='first-seen', value=first_seen),
            Attribute(label='last-seen', value=last_seen),
        ]

        hunt_name = f"historic_{ip}"
        hunt_name = f"{self.__class__.__name__.lower()}-{hunt_name}"
        has.append(Attribute(label='hunt-name', value=hunt_name))

        hunt = Entity(
            label='enrichment',
            has = has,
            # // players = {'enriches': [ip_ent]},
        )
        added_hunt = dbc.add_thing(hunt, return_things=True)

        active_hunts = { endpoint: [added_hunt]}
        hunt_results = {
            endpoint: {
                hunt_name : {
                    'hunt': added_hunt,
                    'found': search_res,
                    'cached': False,
                }
            }
        }

        # from pprint import pprint
        # pprint(hunt_results)

        self.bulk_add_hunt_results(dbc=dbc, hunt_results=hunt_results, force=force)

        return active_hunts, hunt_results

    #################################################
    ### Data Parsing Functions
    #################################################
    def new_parse_hosts_search(
        self,
        raw: Dict = {},
        api_conf: Optional[APIConfig] = None,
        check_dates: Optional[List]=[],
    ):
        all_things = []
        _log = self.logger
        _log.info(f"Running new parsers for /shodan/host/search/ results...")
        if 'total' not in raw:
            _log.error(f"Expected 'total' in response: {raw}")
            return all_things
        parsing_rules = {
            'attributes': [
                {'jsonpath': '$.ip_str', 'label': 'ip-address'},
                {'jsonpath': '$.last_update', 'label': 'last-update'},
                {'jsonpath': '$.tags[*]', 'label': 'tag'}
            ],
            'entities': [
                {'label': 'hostname', 'has': [
                    {'jsonpath': '$.hostnames[*]', 'label': 'fqdn'},
                    {'jsonpath': '$.ip_str', 'label': 'ledsrc'}
                ]},
                {'label': 'domain', 'has': [
                    {'jsonpath': '$.domains[*]', 'label': 'domain-name'},
                    {'jsonpath': '$.ip_str', 'label': 'ledsrc'}
                ]},
                {'label': 'geoloc', 'has': [
                    {'jsonpath': '$.location.city', 'label': 'city'},
                    {'jsonpath': '$.location.region_code', 'label': 'province'},
                    {'jsonpath': '$.location.country_code', 'label': 'country-code'},
                    {'jsonpath': '$.location.country_name', 'label': 'country'},
                    {'jsonpath': '$.location.latitude', 'label': 'latitude'},
                    {'jsonpath': '$.location.longitude', 'label': 'longitude'},
                    {'jsonpath': '$.location.postal_code', 'label': 'postal-code'},
                    {'jsonpath': '$.ip_str', 'label': 'ledsrc'},
                ]},
                {'label': 'autonomous-system', 'has': [
                    {'jsonpath': '$.asn', 'label': 'as-number'},
                    {'jsonpath': '$.isp', 'label': 'isp'},
                    {'jsonpath': '$.org', 'label': 'as-name'},
                    {'jsonpath': '$.location.country_code', 'label': 'country-code'},
                    {'jsonpath': '$.ip_str', 'label': 'ledsrc'},
                ]},
                {'label': 'network-service', 'has': [
                    {'jsonpath': '$.port', 'label': 'port'},
                    {'jsonpath': '$.product', 'label': 'product'},
                    {'jsonpath': '$.version', 'label': 'version'},
                    {'jsonpath': '$.data', 'label': 'service-header'},
                    {'jsonpath': '$.timestamp', 'label': 'date-seen'},
                    {'jsonpath': '$.cpe23[*]', 'label': 'cpe23'},
                    {'jsonpath': '$.hash', 'label': 'shodan-hash'},
                    {'jsonpath': '$.hostnames[*]', 'label': 'fqdn'},
                    {'jsonpath': '$.domains[*]', 'label': 'domain-name'},
                    {'jsonpath': '$.ip_str', 'label': 'ip-address'},
                    {'jsonpath': '$.ip_str', 'label': 'ledsrc'},
                ]},
                {'label': 'ssh', 'has': [
                    {'jsonpath': '$.ssh.cipher', 'label': 'cipher'},
                    {'jsonpath': '$.ssh.fingerprint', 'label': 'fingerprint'},
                    {'jsonpath': '$.ssh.kex.kex_algorithms[*]', 'label': 'kex-algorithm'},
                    {'jsonpath': '$.ssh.kex.encryption_algorithms[*]', 'label': 'encryption-algorithm'},
                    {'jsonpath': '$.ssh.kex.mac_algorithms[*]', 'label': 'mac-algorithm'},
                    {'jsonpath': '$.ssh.kex.compression_algorithms[*]', 'label': 'compression-algorithm'},
                    {'jsonpath': '$.ip_str', 'label': 'ledsrc'}
                ]},
                {'label': 'http', 'has': [
                    {'jsonpath': '$.http.server', 'label': 'http-server'},
                    {'jsonpath': '$.http.host', 'label': 'http-host'},
                    {'jsonpath': '$.http.location', 'label': 'http-location'},
                    {'jsonpath': '$.http.title', 'label': 'http-title'},
                    {'jsonpath': '$.http.headers_hash', 'label': 'http-headers-hash'},
                    {'jsonpath': '$.http.html_hash', 'label': 'http-html-hash'},
                    {'jsonpath': '$.ip_str', 'label': 'ledsrc'}
                ]},
                {'label': 'ip', 'has': [
                    {'jsonpath': '$.ip_str', 'label': 'ip-address'},
                    {'jsonpath': '$.last_update', 'label': 'last-seen'},
                    {'jsonpath': '$.tags[*]', 'label': 'tag'},
                    {'jsonpath': '$.ip_str', 'label': 'ledsrc'},
                ]},
                {'label': 'vulns', 'has': [
                    {'jsonpath': '$.vulns[*]', 'label': 'cve'},
                    {'jsonpath': '$.last_update', 'label': 'last-seen'},
                    {'jsonpath': '$.ip_str', 'label': 'ledsrc'},
                ]},
                {'label': 'ssl', 'has': [
                    {'jsonpath': '$.ssl.jarm', 'label': 'jarm-fingerprint'},
                    {'jsonpath': '$.ssl.ja3s', 'label': 'ja3s'},
                    {'jsonpath': '$.ssl.cert.fingerprint.sha256', 'label': 'fingerprint'},
                    {'jsonpath': '$.ssl.cert.subject.CN', 'label': 'subject-cn'},
                    {'jsonpath': '$.ssl.cert.subject.L', 'label': 'subject-l'},
                    {'jsonpath': '$.ssl.cert.subject.O', 'label': 'subject-o'},
                    {'jsonpath': '$.ssl.cert.subject.C', 'label': 'subject-c'},
                    {'jsonpath': '$.ssl.cert.subject.ST', 'label': 'subject-st'},
                    {'jsonpath': '$.ssl.cert.subject.OU', 'label': 'subject-ou'},
                    {'jsonpath': '$.ssl.cert.issuer.CN', 'label': 'issuer-cn'},
                    {'jsonpath': '$.ssl.cert.issuer.L', 'label': 'issuer-l'},
                    {'jsonpath': '$.ssl.cert.issuer.O', 'label': 'issuer-o'},
                    {'jsonpath': '$.ssl.cert.issuer.C', 'label': 'issuer-c'},
                    {'jsonpath': '$.ssl.cert.issuer.ST', 'label': 'issuer-st'},
                    {'jsonpath': '$.ssl.cert.issuer.OU', 'label': 'issuer-ou'},
                    {'jsonpath': '$.ssl.cipher.name', 'label': 'cipher-name'},
                    {'jsonpath': '$.ssl.cipher.bits', 'label': 'cipher-bits'},
                    {'jsonpath': '$.ssl.cipher.version', 'label': 'version'},
                    {'jsonpath': '$.ssl.cert.pubkey.bits', 'label': 'pubkey-bits'},
                    {'jsonpath': '$.ssl.cert.pubkey.type', 'label': 'pubkey-type'},
                    {'jsonpath': '$.ssl.cert.sig_alg', 'label': 'sig-alg'},
                    {'jsonpath': '$.ssl.cert.issued', 'label': 'issued-date'},
                    {'jsonpath': '$.ssl.cert.expires', 'label': 'expires-date'},
                    {'jsonpath': '$.ssl.versions[*]', 'label': 'version'},
                    {'jsonpath': '$.ip_str', 'label': 'ledsrc'}
                ]}
            ],
            'relations': [],
        }

        for match in raw['matches']:
            parsed_results = self.process_parsing_rules(match, parsing_rules)
            for _, things in parsed_results.items():
                # things = self.new_parse_hosts(dr_match)
                for thing in things:
                    if thing not in all_things:
                        all_things.append(thing)
        return all_things

    def new_parse_hosts(
        self,
        raw: Dict = {},
        api_conf: Optional[APIConfig] = None,
        check_dates: Optional[List]=[],
    ):
        _log = self.logger
        all_things = []
        parsing_rules = {
            'attributes': [
                {'jsonpath': '$.ip_str', 'label': 'ip-address'},
                {'jsonpath': '$.last_update', 'label': 'last-update'},
                {'jsonpath': '$.tags[*]', 'label': 'tag'}
            ],
            'entities': [
                {'label': 'hostname', 'has': [
                    {'jsonpath': '$.hostnames[*]', 'label': 'fqdn'},
                    {'jsonpath': '$.ip_str', 'label': 'ledsrc'}
                ]},
                {'label': 'domain', 'has': [
                    {'jsonpath': '$.domains[*]', 'label': 'domain-name'},
                    {'jsonpath': '$.ip_str', 'label': 'ledsrc'}
                ]},
                {'label': 'geoloc', 'has': [
                    {'jsonpath': '$.location.city', 'label': 'city'},
                    {'jsonpath': '$.location.region_code', 'label': 'province'},
                    {'jsonpath': '$.location.country_code', 'label': 'country-code'},
                    {'jsonpath': '$.location.country_name', 'label': 'country'},
                    {'jsonpath': '$.location.latitude', 'label': 'latitude'},
                    {'jsonpath': '$.location.longitude', 'label': 'longitude'},
                    {'jsonpath': '$.location.postal_code', 'label': 'postal-code'},
                    {'jsonpath': '$.ip_str', 'label': 'ledsrc'},
                ]},
                {'label': 'autonomous-system', 'has': [
                    {'jsonpath': '$.asn', 'label': 'as-number'},
                    {'jsonpath': '$.isp', 'label': 'isp'},
                    {'jsonpath': '$.org', 'label': 'as-name'},
                    {'jsonpath': '$.location.country_code', 'label': 'country-code'},
                    {'jsonpath': '$.ip_str', 'label': 'ledsrc'},
                ]},
                {'label': 'network-service', 'multipath': '$.data[*]', 'has': [
                    {'jsonpath': '$.port', 'label': 'port'},
                    {'jsonpath': '$.product', 'label': 'product'},
                    {'jsonpath': '$.version', 'label': 'version'},
                    {'jsonpath': '$.data', 'label': 'service-header'},
                    {'jsonpath': '$.timestamp', 'label': 'date-seen'},
                    {'jsonpath': '$.cpe23[*]', 'label': 'cpe23'},
                    {'jsonpath': '$.hash', 'label': 'shodan-hash'},
                    {'jsonpath': '$.hostnames[*]', 'label': 'fqdn'},
                    {'jsonpath': '$.domains[*]', 'label': 'domain-name'},
                    {'jsonpath': '$.ip_str', 'label': 'ip-address'},
                    {'jsonpath': '$.ip_str', 'label': 'ledsrc'},
                ]},
                {'label': 'ssh', 'multipath': '$.data[*]', 'has': [
                    {'jsonpath': '$.ssh.cipher', 'label': 'cipher'},
                    {'jsonpath': '$.ssh.fingerprint', 'label': 'fingerprint'},
                    {'jsonpath': '$.ssh.kex.kex_algorithms[*]', 'label': 'kex-algorithm'},
                    {'jsonpath': '$.ssh.kex.encryption_algorithms[*]', 'label': 'encryption-algorithm'},
                    {'jsonpath': '$.ssh.kex.mac_algorithms[*]', 'label': 'mac-algorithm'},
                    {'jsonpath': '$.ssh.kex.compression_algorithms[*]', 'label': 'compression-algorithm'},
                    {'jsonpath': '$.ip_str', 'label': 'ledsrc'}
                ]},
                {'label': 'http', 'multipath': '$.data[*]', 'has': [
                    {'jsonpath': '$.http.server', 'label': 'http-server'},
                    {'jsonpath': '$.http.host', 'label': 'http-host'},
                    {'jsonpath': '$.http.location', 'label': 'http-location'},
                    {'jsonpath': '$.http.title', 'label': 'http-title'},
                    {'jsonpath': '$.http.headers_hash', 'label': 'http-headers-hash'},
                    {'jsonpath': '$.http.html_hash', 'label': 'http-html-hash'},
                    {'jsonpath': '$.ip_str', 'label': 'ledsrc'}
                ]},
                {'label': 'ip', 'has': [
                    {'jsonpath': '$.ip_str', 'label': 'ip-address'},
                    {'jsonpath': '$.last_update', 'label': 'last-seen'},
                    {'jsonpath': '$.tags[*]', 'label': 'tag'},
                    {'jsonpath': '$.ip_str', 'label': 'ledsrc'},
                ]},
                {'label': 'vulns', 'has': [
                    {'jsonpath': '$.vulns[*]', 'label': 'cve'},
                    {'jsonpath': '$.ip_str', 'label': 'ledsrc'},
                    {'jsonpath': '$.last_update', 'label': 'last-seen'},
                ]},
                {'label': 'ssl', 'multipath': '$.data[*]', 'has': [
                    {'jsonpath': '$.ssl.jarm', 'label': 'jarm-fingerprint'},
                    {'jsonpath': '$.ssl.ja3s', 'label': 'ja3s'},
                    {'jsonpath': '$.ssl.cert.fingerprint.sha256', 'label': 'fingerprint'},
                    {'jsonpath': '$.ssl.cert.subject.CN', 'label': 'subject-cn'},
                    {'jsonpath': '$.ssl.cert.subject.L', 'label': 'subject-l'},
                    {'jsonpath': '$.ssl.cert.subject.O', 'label': 'subject-o'},
                    {'jsonpath': '$.ssl.cert.subject.C', 'label': 'subject-c'},
                    {'jsonpath': '$.ssl.cert.subject.ST', 'label': 'subject-st'},
                    {'jsonpath': '$.ssl.cert.subject.OU', 'label': 'subject-ou'},
                    {'jsonpath': '$.ssl.cert.issuer.CN', 'label': 'issuer-cn'},
                    {'jsonpath': '$.ssl.cert.issuer.L', 'label': 'issuer-l'},
                    {'jsonpath': '$.ssl.cert.issuer.O', 'label': 'issuer-o'},
                    {'jsonpath': '$.ssl.cert.issuer.C', 'label': 'issuer-c'},
                    {'jsonpath': '$.ssl.cert.issuer.ST', 'label': 'issuer-st'},
                    {'jsonpath': '$.ssl.cert.issuer.OU', 'label': 'issuer-ou'},
                    {'jsonpath': '$.ssl.cipher.name', 'label': 'cipher-name'},
                    {'jsonpath': '$.ssl.cipher.bits', 'label': 'cipher-bits'},
                    {'jsonpath': '$.ssl.cipher.version', 'label': 'version'},
                    {'jsonpath': '$.ssl.cert.pubkey.bits', 'label': 'pubkey-bits'},
                    {'jsonpath': '$.ssl.cert.pubkey.type', 'label': 'pubkey-type'},
                    {'jsonpath': '$.ssl.cert.sig_alg', 'label': 'sig-alg'},
                    {'jsonpath': '$.ssl.cert.issued', 'label': 'issued-date'},
                    {'jsonpath': '$.ssl.cert.expires', 'label': 'expires-date'},
                    {'jsonpath': '$.ssl.versions[*]', 'label': 'version'},
                    {'jsonpath': '$.ip_str', 'label': 'ledsrc'}
                ]}
            ],
            'relations': [],
        }


        _log.debug(f"attr: {len(parsing_rules['attributes'])} ent: {len(parsing_rules['entities'])} rel: {len(parsing_rules['relations'])}")
        parsed_result = self.process_parsing_rules(raw, parsing_rules)
        for _, things in parsed_result.items():
            for thing in things:
                if thing not in all_things:
                    all_things.append(thing)

        return all_things

    def parse_hosts_search(
        self,
        raw: Dict = {},
        api_conf: Optional[APIConfig] = None,
        check_dates: Optional[List]=[],
    ):
        """
        Possibly more parsing to do here, but I imagine it'll mostly be picked
        up by searches of specific hosts
        """
        things = []
        _log = self.logger
        _log.info(f"Parsing /shodan/host/search/ results..")

        response = raw # it's just easier to do this than find/replace
        if 'total' not in response:
            _log.error(f"Expected 'total' in response: {response}")
            return things

        date_seen = None
        last_updated = None
        for match in response['matches']:
            # Setup max last-seen value for latest date-seen attribute on hunt
            match['timestamp'] = self._format_date(match['timestamp'])
            if not date_seen or match['timestamp'] > date_seen:
                date_seen = match['timestamp']
                if check_dates:
                    if date_seen in check_dates:
                        return date_seen
                    else:
                        return False
                last_updated = Attribute(label='date-seen', value=date_seen)

            data=copy.deepcopy(match)

            host_ip = Attribute(label='note', value=data['ip_str'])
            # Add IP
            dka = {
                'ip_str': 'ip-address',
                'timestamp': 'date-seen',
            }
            has = []

            # Add associated domains as notes for reference
            if data.get('domains'):
                dom_notes = data.get('domains')
                for dn in dom_notes:
                    domain_note = Attribute(label='note', value=dn)
                    if domain_note not in has:
                        has.append(domain_note)

            ent_ip = self._generate_entity_from_data(
                data=data,
                datakey_attrlbls=dka,
                label='ip',
                has=has,
            )
            ent_ip = self.check_dateseen(ent_ip, last_updated)
            if ent_ip not in things:
                things.append(ent_ip)

            # Add hostnames
            if 'hostnames' in data:
                for hn in data['hostnames']:
                    fqdn = Attribute(label='fqdn', value=hn)
                    has=[host_ip, fqdn]
                    dka = {
                        'timestamp': 'date-seen',
                    }
                    hn_ent = self._generate_entity_from_data(
                        data=data,
                        datakey_attrlbls=dka,
                        label='hostname',
                        has=has,
                    )
                    hn_ent = self.check_dateseen(hn_ent, last_updated)
                    if hn_ent not in things:
                        things.append(hn_ent)

            # Add domains
            if 'domains' in data:
                for dom in data['domains']:
                    domain_name = Attribute(label='domain-name', value=dom)
                    has=[host_ip, domain_name]
                    dka = {
                        'timestamp': 'date-seen',
                    }
                    dom_ent = self._generate_entity_from_data(
                        data=data,
                        datakey_attrlbls=dka,
                        label='domain',
                        has=has,
                    )
                    dom_ent = self.check_dateseen(dom_ent, last_updated)
                    if dom_ent not in things:
                        things.append(dom_ent)


            if 'location' in data:
                data = copy.deepcopy(match['location'])
                dka = {
                    'city': 'city',
                    'region_code': 'province',
                    'country_code': 'country-code',
                    'country_name': 'country',
                    # // 'postal_code': 'postal-code',
                }
                has = [host_ip]
                rel = self._generate_entity_from_data(
                    data=data,
                    datakey_attrlbls=dka,
                    label='geoloc',
                    has=has,
                    # // players = {'located-in': [ent_ip]},
                )
                if rel.keyattr=='comboid':
                    comboid = rel.get_comboid()
                    rel.has.append(comboid)
                if rel not in things:
                    things.append(rel)

            # ASN
            data = copy.deepcopy(match)
            cc = Attribute(
                label='country-code',
                value=data['location']['country_code']
            )
            dka = {
                'asn': 'as-number',
                'isp': 'isp',
                'org': 'as-name',
                'timestamp': 'date-seen',
            }
            has = [cc, host_ip]
            rel_asn = self._generate_entity_from_data(
                data=data,
                datakey_attrlbls=dka,
                label='autonomous-system',
                has=has,
                #// players = {
                #//     'linked': [ent_ip],
                #// }
            )
            # _log.debug(f"rel_asn: {rel_asn.to_dict()}")
            asn_safe_copy = copy.deepcopy(rel_asn.has)
            for attr in asn_safe_copy:
                if attr.label=='as-number' and attr.value.startswith('AS'):
                    rel_asn.has.remove(attr)
                    new_attr = Attribute(
                        label='as-number',
                        value=attr.value.lstrip('AS')
                    )
                    rel_asn.has.append(new_attr)
            rel_asn = self.check_dateseen(rel_asn, last_updated)
            if rel_asn.keyattr == 'comboid':
                comboid = rel_asn.get_comboid()
                rel_asn.has.append(comboid)
            if rel_asn not in things:
                things.append(rel_asn)

        if last_updated:
            things.append(last_updated)
        while None in things:
            things.remove(None)
        return things

    def parse_historic_host(
        self,
        raw: Dict = {},
        api_conf: Optional[APIConfig] = None,
        check_dates: Optional[List]=[],
        first_seen: datetime = None,
        last_seen: datetime = None,
    ):
        _log = self.logger

        things = []

        response = raw

        # Only keep data points between specific dates
        pruned_dict = {'data': []}
        for k,v in response.items():
            if k=='data':
                for dp in v:
                    ts = self._format_date(dp['timestamp'])
                    if first_seen<=ts<=last_seen:
                        pruned_dict['data'].append(dp)
            else:
                pruned_dict[k]=v

        # _log.info(f"pruned_dict: {pformat(pruned_dict)}")

        things = self.parse_hosts(pruned_dict)
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

        _log.info(f"Parsing host results...")
        # _log.info(f"results:\n {pformat(response)}")
        if not response:
            _log.warning(f"No results found!")
            return things

        last_updated = None
        if 'last_update' in response:
            val = self._format_date(response['last_update'])
            if val is not None:
                if check_dates:
                    if val in check_dates:
                        return val
                    else:
                        return False
                response['last_update'] = self._format_date(
                    response['last_update']
                )
                # add last seen
                last_updated = Attribute(label='date-seen', value=val)
                things.append(last_updated)
            else:
                if check_dates:
                    return False

        if 'tags' in response and response['tags']:
            for tag in response['tags']:
                t = Attribute(label='tag', value=tag)
                things.append(t)

        data = response
        # Add IP
        host_ip = Attribute(label='note', value=data['ip_str'])
        if 'ip_str' in data:
            dka = {
                'ip_str': 'ip-address',
                'timestamp': 'date-seen',
            }
            has = []
            ent_ip = self._generate_entity_from_data(
                data=data,
                datakey_attrlbls=dka,
                label='ip',
                has=has,
            )
            if ent_ip not in things:
                things.append(ent_ip)

        # Add hostnames
        if 'hostnames' in data:
            for hn in data['hostnames']:
                fqdn = Attribute(label='fqdn', value=hn)
                has=[host_ip, fqdn]
                dka = {
                    'timestamp': 'date-seen',
                }
                hn_ent = self._generate_entity_from_data(
                    data=data,
                    datakey_attrlbls=dka,
                    label='hostname',
                    has=has,
                )
                hn_ent = self.check_dateseen(hn_ent, last_updated)
                if hn_ent not in things:
                    things.append(hn_ent)

        # Add domains
        if 'domains' in data:
            for dom in data['domains']:
                domain_name = Attribute(label='domain-name', value=dom)
                has=[host_ip, domain_name]
                dka = {
                    'timestamp': 'date-seen',
                }
                dom_ent = self._generate_entity_from_data(
                    data=data,
                    datakey_attrlbls=dka,
                    label='domain',
                    has=has,
                )
                dom_ent = self.check_dateseen(dom_ent, last_updated)
                if dom_ent not in things:
                    things.append(dom_ent)

        # Add geoloc
        dka = {
            'city': 'city',
            'region_code': 'province',
            'country_code': 'country-code',
            'country_name': 'country',
            'postal_code': 'postal-code',
        }
        has = [host_ip]
        rel = self._generate_entity_from_data(
            data=data,
            datakey_attrlbls=dka,
            label='geoloc',
            has=has,
            # // players = {'located-in': [ent_ip]},
        )
        if rel.keyattr == 'comboid':
            comboid = rel.get_comboid()
            rel.has.append(comboid)
        if rel not in things:
            things.append(rel)

        # Add ASN
        dka = {
            'asn': 'as-number',
            'isp': 'isp',
            'org': 'as-name',
            'country_code': 'country-code',
            'timestamp': 'date-seen',
        }
        has = [host_ip]
        rel_asn = self._generate_entity_from_data(
            data=data,
            datakey_attrlbls=dka,
            label='autonomous-system',
            has=has,
            #!! players = {
            #!!     'linked': [ent_ip],
            #!! }
        )
        asn_safe_copy = copy.deepcopy(rel_asn.has)
        for attr in asn_safe_copy:
            if attr.label=='as-number' and attr.value.startswith('AS'):
                rel_asn.has.remove(attr)
                new_attr = Attribute(
                    label='as-number',
                    value=attr.value.lstrip('AS')
                )
                rel_asn.has.append(new_attr)
        # _log.debug(f"rel_asn: {rel_asn.to_dict()}")
        rel_asn = self.check_dateseen(rel_asn, last_updated)
        if rel_asn.keyattr == 'comboid':
            comboid = rel_asn.get_comboid()
            rel_asn.has.append(comboid)
        if rel_asn not in things:
            things.append(rel_asn)

        # Add OS
        if 'os' in data and data['os']:
            attr = Attribute(label='product', value=data['os'])
            # hope this doesn't break it - should attach 'product'
            # attr to 'enrichment' entity
            things.append(attr)

        # Add Version
        if 'version' in data and data['version']:
            attr = Attribute(label='version', value=data['version'])
            things.append(attr)

        #######################################################################
        #### Process Services
        #### There are... so... so many....
        #### https://datapedia.shodan.io/
        #### https://datapedia.shodan.io/banner.schema.json
        #### Let's start with a few and go from there...
        #######################################################################
        for service in response['data']:
            provider = Attribute(
                label='service-provider',
                value=str(self.__class__.__name__)
            )
            dateval = self._format_date(service['timestamp'])
            seen = Attribute(label='date-seen', value=dateval)
            data = service
            # basics
            dka = {
                'data': 'service-header',
                'timestamp': 'date-seen',
                'port': 'port',
            }
            has = [provider, host_ip, seen]
            service_rel = self._generate_entity_from_data(
                data=data,
                datakey_attrlbls=dka,
                label='network-service',
                has=has,
                #!! players = {
                #!!     'running-on': [ent_ip],
                #!!     'serves': [],
                #!!     'related': [],
                #!! }
            )

            # Add hostnames
            if 'hostnames' in data and data['hostnames']:
                for hn in data['hostnames']:
                    attr = Attribute(label='fqdn', value=hn)
                    service_rel.has.append(attr)

            # Add domains
            if 'domains' in data and data['domains']:
                for dom in data['domains']:
                    attr = Attribute(label='domain-name', value=dom)
                    service_rel.has.append(attr)

            # Product
            if 'product' in service and service['product']:
                attr = Attribute(label='product', value=service['product'])
                service_rel.has.append(attr)
            # Hash
            if 'hash' in service and service['hash']:
                attr = Attribute(label='shodan-hash', value=str(service['hash']))
                service_rel.has.append(attr)
            # CPE23
            if 'cpe23' in service:
                for cpe in service['cpe23']:
                    attr = Attribute(label='cpe23', value=cpe)
                    service_rel.has.append(attr)
            # Service OS
            if 'os' in service and service['os']:
                attr = Attribute(label='product', value=service['os'])
                service_rel.has.append(attr)

            # ssh
            if 'ssh' in service:
                ssh_data = service['ssh']
                attr = Attribute(label='fingerprint', value=ssh_data['hassh'])
                service_rel.has.append(attr)

            # http
            if 'http' in service:
                http_data = service['http']
                # Convert hashes to strings
                if 'robots_hash' in http_data and http_data['robots_hash']:
                    http_data['robots_hash'] = str(http_data['robots_hash'])
                if 'securitytxt_hash' in http_data and http_data['securitytxt_hash']:
                    http_data['securitytxt_hash'] = str(http_data['securitytxt_hash'])
                if 'sitemap_hash' in http_data and http_data['sitemap_hash']:
                    http_data['sitemap_hash'] = str(http_data['sitemap_hash'])
                if 'headers_hash' in http_data and http_data['headers_hash']:
                    http_data['headers_hash'] = str(http_data['headers_hash'])
                if 'html_hash' in http_data and http_data['html_hash']:
                    http_data['html_hash'] = str(http_data['html_hash'])

                dka = {
                    'status': 'status-code',
                    'robots_hash': 'http-robots-hash',
                    'securitytxt_hash': 'http-securitytxt-hash',
                    'title': 'http-title',
                    'sitemap_hash': 'http-sitemap-hash',
                    'headers_hash': 'http-headers-hash',
                    # 'html': 'http-html', # Commenting out because of string limits
                    'html_hash': 'http-html-hash',
                }
                has = [host_ip, seen]
                if 'server' in http_data and http_data['server']:
                    keyval = f"Server: {http_data['server']}"
                    server_header = Attribute(
                        label='http-header-pair',
                        value=keyval
                    )
                    has.append(server_header)
                if 'location' in http_data and http_data['location']:
                    keyval = f"Location: {http_data['location']}"
                    loc_header = Attribute(
                        label='http-header-pair',
                        value=keyval
                    )
                    has.append(loc_header)
                if 'host' in http_data and http_data['host']:
                    keyval = f"Host: {http_data['host']}"
                    header = Attribute(
                        label='http-header-pair',
                        value=keyval
                    )
                    has.append(header)
                http_ent = self._generate_entity_from_data(
                    data=http_data,
                    datakey_attrlbls=dka,
                    label='http',
                    has=has,
                )
                # // service_rel.players['serves'].append(http_ent)
                things.append(http_ent)
                service_rel.has += http_ent.has

            # SSL
            if 'ssl' in service:
                ssl_data = service['ssl']
                # JARM
                if 'jarm' in ssl_data and ssl_data['jarm']:
                    jarm_fingerprint = Attribute(
                        label='jarm-fingerprint',
                        value=ssl_data['jarm']
                    )
                    has = [seen, jarm_fingerprint]
                    jarm_ent = Entity(label='jarm', has=has)
                    # // service_rel.players['serves'].append(jarm_ent)
                    things.append(jarm_ent)
                    service_rel.has.append(jarm_fingerprint)

                # Manually build all attributes b/c I don't
                # have a better way to do it
                has = []
                # JA3
                if 'ja3s' in ssl_data and ssl_data['ja3s']:
                    ja3 = Attribute(label='ja3s', value=ssl_data['ja3s'])
                    has.append(ja3)
                # Fingerprint
                attr = Attribute(
                    label='fingerprint',
                    value=ssl_data['cert']['fingerprint']['sha256']
                )
                has.append(attr)
                # Subject
                for k, val in ssl_data['cert']['subject'].items():
                    attr = None
                    if k == "CN":
                        attr = Attribute(
                            label='subject-cn',
                            value=val
                        )
                    elif k == "L":
                        attr = Attribute(
                            label='subject-l',
                            value=val
                        )
                    elif k == "O":
                        attr = Attribute(
                            label='subject-o',
                            value=val
                        )
                    elif k == "C":
                        attr = Attribute(
                            label='subject-c',
                            value=val
                        )
                    elif k == "ST":
                        attr = Attribute(
                            label='subject-st',
                            value=val
                        )
                    elif k == "OU":
                        attr = Attribute(
                            label='subject-ou',
                            value=val
                        )
                    if attr:
                        has.append(attr)
                # Issuer
                for k, val in ssl_data['cert']['issuer'].items():
                    attr = None
                    if k == "CN":
                        attr = Attribute(
                            label='issuer-cn',
                            value=val
                        )
                    elif k == "L":
                        attr = Attribute(
                            label='issuer-l',
                            value=val
                        )
                    elif k == "O":
                        attr = Attribute(
                            label='issuer-o',
                            value=val
                        )
                    elif k == "C":
                        attr = Attribute(
                            label='issuer-c',
                            value=val
                        )
                    elif k == "ST":
                        attr = Attribute(
                            label='issuer-st',
                            value=val
                        )
                    elif k == "OU":
                        attr = Attribute(
                            label='issuer-ou',
                            value=val
                        )
                    if attr:
                        has.append(attr)

                # Cipher
                attr = Attribute(
                    label='cipher-name',
                    value=ssl_data['cipher']['name']
                )
                has.append(attr)
                attr = Attribute(
                    label='cipher-bits',
                    value=str(ssl_data['cipher']['bits'])
                )
                has.append(attr)
                attr = Attribute(
                    label='version',
                    value=ssl_data['cipher']['version']
                )
                has.append(attr)

                # Pubkey
                attr = Attribute(
                    label='pubkey-bits',
                    value=int(ssl_data['cert']['pubkey']['bits'])
                )
                has.append(attr)
                attr = Attribute(
                    label='pubkey-type',
                    value=ssl_data['cert']['pubkey']['type']
                )

                # Signature Algorithm
                attr = Attribute(
                    label='sig-alg',
                    value=ssl_data['cert']['sig_alg']
                )
                has.append(attr)

                # Issued/Expired
                dateval = self._format_date(ssl_data['cert']['issued'])
                attr = Attribute(
                    label='issued-date',
                    value=dateval
                )
                has.append(attr)
                dateval = self._format_date(ssl_data['cert']['expires'])
                attr = Attribute(
                    label='expires-date',
                    value=dateval
                )
                has.append(attr)

                # Versions
                for version in ssl_data['versions']:
                    attr = Attribute(
                        label='version',
                        value=version
                    )
                    has.append(attr)

                # Cert Ent
                has.append(seen)
                cert_ent = Entity(
                    label='ssl',
                    has=has,
                )

                # // service_rel.players['serves'].append(cert_ent)
                service_rel.has += has
                things.append(cert_ent)

            ####################################################################
            #### Additional Services Parsing
            #### These will probably be added on an as-needed basis
            ####################################################################

            # FTP
            # TODO

            # DNS
            # TODO

            # Cobalt_Strike_Beacon
            # TODO

            '''
            first check if service_rel is already in things after temporarily removing the IP address.
            If so, pop, merge, and re-add with both IPs.
            '''
            """
            if service_rel in things:
                first_thing = things.pop(things.index(service_rel))
                second_thing = service_rel
                merged_thing = first_thing.merge(**second_thing)
                _log.debug(f"first_thing: {first_thing}\n\t{pformat(first_thing.to_dict())}")
                _log.debug(f"second_thing: {second_thing}\n\t{pformat(second_thing.to_dict())}")
                _log.debug(f"merged thing: {merged_thing}\n\t{pformat(merged_thing.to_dict())}")
                service_rel = merged_thing
            """
            things.append(service_rel)



        while None in things:
            things.remove(None)

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
        # * if the page parameter isn't set (or set to zero) we're not going to
        # * paginate the results, just return the first set like normal.
        if not api_conf.paginate:
            return search_res

        # * If we've gone past our max_pages count, stop collecting
        # _log.info(f"CURRENT PAGE_COUNT: {api_conf.page_count}")
        if api_conf.page_count >= self.max_pages:
            return search_res

        # * Calculate how many pages we need to get all the results
        total_results = search_res['raw']['total']
        f_val = total_results/self.results_per_page
        pages_needed = int(f_val) + (1 if f_val - int(f_val) > 0 else 0)
        current_page = api_conf.page_count
        if current_page >= pages_needed:
            return search_res

        # @ If you've made it this far, we still have pages to request.
        # @ Advance the counters and let 'er rip.
        next_page = int(current_page)+1
        api_conf.params['page']=next_page
        api_conf.page_count += 1
        # _log.info(f"NEW PAGE COUNT: {api_conf.page_count}")

        if pages_needed <= self.max_pages:
            x = f"{pages_needed} pages TOTAL."
        else:
            x = f"{self.max_pages} pages allowed by the max_pages config."

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

        if api_conf.endpoint=='hosts_search':
            counter = 1
            for r in raw:
                chunk = {
                    'total': r['total'],
                    'result': 0,
                    'plugin': 'shodan',
                    'endpoint': api_conf.endpoint,
                    'query': api_conf.params.get(api_conf.param_query_key),
                    'chunking_time': int(time()),
                    'hit': None,
                }
                for match in r['matches']:
                    new_chunk = copy.deepcopy(chunk)
                    new_chunk['result'] = counter
                    new_chunk['chunking_time'] = int(time())
                    new_chunk['hit'] = match
                    chunks.append(new_chunk)
                    counter += 1

        return chunks


    #### TODO

    #################################################
    ### hunt or Kill Logical Functions
    #################################################

    def hok_hosts(
        self,
        thing: Entity = None,
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
