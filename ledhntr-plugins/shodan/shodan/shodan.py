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
            # ! parser = self.parse_hosts_search,
            parser = self.new_parse_hosts_search,
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
            # ! parser = self.parse_hosts,
            parser = self.new_parse_hosts,
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

        # @ Normalization Tweaks
        # ; ASNs remove leading "AS"
        atc = copy.deepcopy(all_things)
        for thing in atc:
            if thing.label == "as-number" and thing.value.startswith("AS"):
                new_attr = Attribute(
                    label='as-number',
                    value=thing.value.lstrip('AS')
                )
                all_things.remove(thing)
                all_things.append(new_attr)

        # @ Add Metadata
        now = datetime.now()
        now = self._format_date(now)
        for thing in all_things:
            nowattr = Attribute(label='date-seen', value=now)
            thing.has.append(nowattr)

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

        # @ Normalization Tweaks
        # ; ASNs remove leading "AS"
        atc = copy.deepcopy(all_things)
        for thing in atc:
            if thing.label == "as-number" and thing.value.startswith("AS"):
                new_attr = Attribute(
                    label='as-number',
                    value=thing.value.lstrip('AS')
                )
                all_things.remove(thing)
                all_things.append(new_attr)

        # @ Add Metadata
        now = datetime.now()
        now = self._format_date(now)
        for thing in all_things:
            nowattr = Attribute(label='date-seen', value=now)
            thing.has.append(nowattr)

        while None in all_things:
            all_things.remove(None)

        # TODO - do I need to add check_dates in from before?
        # TODO - I feel like check_dates and api_conf had a purpose that I'm forgetting

        return all_things

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

        things = self.new_parse_hosts(pruned_dict)
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
