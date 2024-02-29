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

        key = config.get(
            'options',
            'key',
            fallback = 'key',
        )

        secret = config.get(
            'options',
            'secret',
            fallback = "secret",
        )

        self.auth = (key, secret)
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
                "per_page": 100,
                "virtual_hosts": "EXCLUDE", # EXLUDE|INCLUDE|ONLY
                "cursor": None,
            },
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
            parser = self.parse_hosts,
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
