"""
Overview
========

Use this plugin to interact with the Zetalytics API

"""

import logging
import requests

from pprint import pformat
from datetime import datetime, timezone, timedelta
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

class Zeta(HNTRPlugin):
    """Zetalytics HNTR Plugin
    Zetalytics API interaction

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
            fallback = 'https://zonecruncher.com/api/',
        )

        self.key = config.get(
            'options',
            'key',
            fallback = '',
        )

        self.days_back = int(config.get(
            'options',
            'days_back',
            fallback = '30'
        ))

        self.ssl_verify = config.get(
            'options',
            'ssl_verify',
            fallback = 'true',
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
            fallback = '1',
        ))

        self._load_api_configs()

    def _load_api_configs(
        self,
    ):
        """Load API configs for this plugin
        """
        _log = self.logger
        self.api_confs = {}

        # Which param carries the default query
        self.param_query_key = "q"
        headers = {
            'Accept': 'application/json',
            'User-Agent': 'LED-HNTR v0.1',
            # 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
        }

        # Consider setting individual default frequencies for each endpoint?
        # Probably over-complicating the issue. If I did want to do that, it
        # should be its own property of APIConfig()

        # Consider adding a find_api_endpoint(acs, search) function to HNTRPlugin?
        # It would be more elegant than constantly looping over self.api_confs
        # every time I wanted a particular config, and would have the added
        # benefit of being able to search for partial endpoint names.
        # I could also add a 'description' field to explain what each endpoint
        # name does explicitly. And perhaps an 'example' field that shows an
        # example return Dict.

        # domain2whois
        '''
        c = APIConfig(
            endpoint = "domain2whois",
            uri = "domain2whois",
            headers = headers,
            params = {
                "q": None,
                # "size": 300, # changing to 25 because 300 can really blow up
                "size": 25,
                "token": self.key,
                "start": self._get_start_date,
                "end": self._get_end_date,
            },
            parser = self.parse_domain2whois,
            add_to_db = self.add_hunt,
            simple_query_types = ["domain"],
            frequency = 24*30*6, # every 6 months if it were actually active
            hunt_active = False,
            hunt_name = "dom2whois_{query}",
        )
        self.api_confs.append(c)
        '''

        # hostname
        c = APIConfig(
            endpoint = "hostname",
            uri = "v2/hostname",
            headers = headers,
            params = {
                "q": None,
                "toBaseDomain": False,
                # "size": 300, # changing to 25 because 300 can really blow up
                "size": 25,
                "csvFields": None,
                "token": self.key,
                "start": self._get_start_date,
                "end": self._get_end_date,
                "tsfield": "all",
            },
            parser = self.parse_hostname,
            add_to_db = self.add_hunt,
            simple_query_types = ["domain"], # limiting to domain to save API queries
            param_query_key=self.param_query_key,
            frequency = self.freq_threshold,
            hunt_active = True,
            hunt_name = "hostname_{query}",
            hok_logic = self.hok_hostname,
        )
        self.api_confs[c.endpoint] = c

        # ip
        c = APIConfig(
            endpoint = "ip",
            uri = "v2/ip",
            headers = headers,
            params = {
                "q" : None,
                # "size": 300, # changing to 25 because 300 can really blow up
                "size": 25,
                "csvFields": None,
                "token": self.key,
                "start": self._get_start_date,
                "end": self._get_end_date,
                "tsfield": "all",
            },
            parser = self.parse_ip,
            add_to_db = self.add_hunt,
            simple_query_types = ["ip"],
            param_query_key=self.param_query_key,
            frequency = self.freq_threshold,
            hunt_active = True,
            hunt_name = "ip_{query}",
            hok_logic = self.hok_ip,
        )
        self.api_confs[c.endpoint] = c

        # d8s
        c = APIConfig(
            endpoint = "domain2d8s",
            uri = "v2/domain2d8s",
            headers = headers,
            params = {
                "q": None,
                # "size": 1, # defaults to 1 for live lookups
                "live": 1,
                "csvFields": None,
                "token": self.key,
                "start": self._get_start_date,
                "end": self._get_end_date,
            },
            parser = self.parse_d8s,
            add_to_db = self.add_hunt,
            simple_query_types = ["domain"], # limiting to domain to save API queries
            param_query_key=self.param_query_key,
            frequency = self.freq_threshold,
            hunt_active = False,
            hunt_name = "d8s_{query}",
            hok_logic = self.hok_d8s,
        )
        self.api_confs[c.endpoint] = c

        # liveDNS
        c = APIConfig(
            endpoint = "livedns",
            uri = "v2/liveDNS",
            headers = headers,
            params = {
                "q": None,
                "toBaseDomain": False,
                "token": self.key,
            },
            parser = None, # TODO
            add_to_db = self.add_hunt,
            simple_query_types = ["domain"], # limiting to domain to save API queries
            param_query_key=self.param_query_key,
            frequency = self.freq_threshold,
            hunt_active = False,
            hunt_name = "livedns_{query}",
            hok_logic = None, # TODO
        )
        self.api_confs[c.endpoint] = c

        # subdomains
        '''
        c = APIConfig(
            endpoint = "subdomains",
            uri = "subdomains",
            headers = headers,
            params = {
                "q" : None,
                "toBaseDomain": False,
                "v": False,
                "vv": False,
                "vvv": True,
                "sort": "first:desc",
                "t": None,
                "csvFields": None,
                "token": self.key,
                "start": self._get_start_date,
                "end": self._get_end_date,
                "tsfield": "all",
            },
            parser = self.parse_subdomains,
            add_to_db = self.add_hunt,
            simple_query_types = ["domain"],
            frequency = self.freq_threshold,
            hunt_active = True,
            hunt_name = "subdoms_{query}",
            hok_logic = self.hok_subdomains,
        )
        self.api_confs.append(c)
        '''

        return self.api_confs

    def _get_start_date(
        self,
        days_back: int=0,
    ):
        """Get date/time from days_back days ago

        :returns datetime: Returns datetime UTC from <days_back> days ago.
        """
        _log = self.logger
        if not days_back:
            days_back = self.days_back
        return str(datetime.now(timezone.utc)-timedelta(days=days_back))

    def _get_end_date(
        self,
    ):
        """Gets the current date/time in UTC

        :returns datetime: Returns datetime object in UTC from <days_back> days go.
        """
        _log = self.logger
        return str(datetime.now(timezone.utc))

    #################################################
    ### Data Parsing Functions
    #################################################

    def parse_hostname(
        self,
        raw: dict = {},
        api_conf: APIConfig = None,
        check_dates: Optional[List]=[],
    ):
        _log = self.logger
        things = []

        cache_date_attr = None
        if 'cacheDate' in raw and raw['cacheDate']:
            val = self._format_date(raw['cacheDate'])
            if val is not None:
                if check_dates:
                    if val in check_dates:
                        return val
                    else:
                        return False
                cache_date_attr = Attribute(
                    label='date-seen',
                    value=val
                )
                things.append(cache_date_attr)
            if check_dates:
                return False

        if 'results' in raw and raw['results']:
            data = raw['results']
            counter = 0
            for res in data:
                dkas = {
                    'date': 'date-seen',
                    'qname': 'fqdn',
                    'value': 'dns-value',
                    'type': 'dns-type',
                    'value_ip': 'ip-address',
                }
                has = []
                resolves = []
                related = []

                date_attr = None
                if 'date' in res:
                    date_attr = Attribute(
                        label='date-seen',
                        value=self._format_date(res['date'])
                    )
                    # has.append(date_attr)

                dom = None
                if 'domain' in res and res['domain']:
                    dom = Attribute(label='domain-name', value=res['domain'])
                    domain = Entity(label='domain', has=[dom])
                    if date_attr:
                        domain.has.append(date_attr)
                    resolves.append(domain)

                    if 'qname' in res:
                        if res['qname'].endswith(f".{res['domain']}"):
                            fqdn = Attribute(label='fqdn', value=res['qname'])
                            hostname = Entity(label='hostname', has=[fqdn])
                            if date_attr:
                                hostname.has.append(date_attr)
                            resolves.append(hostname)

                if 'value_ip' in res and res['value_ip']:
                    ipaddy = Attribute(label='ip-address', value=res['value_ip'])
                    ip = Entity(label='ip', has=[ipaddy])
                    if date_attr:
                        ip.has.append(date_attr)
                    resolves.append(ip)

                if 'type' in res and res['type']:
                    # soa_server
                    if res['type'] == 'soa_server':
                        fqdn = Attribute(label='fqdn', value=res['value'])
                        soa_server = Entity(label='hostname', has=[fqdn])
                        if date_attr:
                            soa_server.has.append(date_attr)
                        resolves.append(soa_server)

                    # soa_email
                    if res['type'] == 'soa_email':
                        email = Attribute(label='email-address', value=res['value'])
                        soa_email = Entity(label='whois', has=[email])
                        if date_attr:
                            soa_email.has.append(date_attr)
                        '''
                        # This requires the whois schema to be updated later than 2022-09-16
                        if dom:
                            soa_email.has.append(dom)
                        '''
                        related.append(soa_email)

                    # ns
                    if res['type'] == 'ns':
                        fqdn = Attribute(label='fqdn', value=res['value'])
                        ns = Entity(label='hostname', has=[fqdn])
                        if date_attr:
                            ns.has.append(date_attr)
                        resolves.append(ns)

                    # mx
                    if res['type'] == 'mx':
                        fqdn = Attribute(label='fqdn', value=res['value'])
                        mx = Entity(label='hostname', has=[fqdn])
                        if date_attr:
                            mx.has.append(date_attr)
                        resolves.append(mx)

                reso_rel = self._generate_relation_from_data(
                    data = res,
                    datakey_attrlbls=dkas,
                    label = 'resolution',
                    has=has,
                    players = {},
                )
                # Make sure all dns-values are strings
                for attr in reso_rel.has:
                    if not attr:
                        continue
                    if not isinstance(attr.value, str):
                        attr._value=str(attr.value)
                if resolves:
                    reso_rel.players['resolves'] = resolves
                if related:
                    reso_rel.players['related'] = related
                # _log.info(f"Adding {reso_rel} to the list of resolutions.")
                # _log.info(f"Resolves: {resolves}")

                things.append(reso_rel)
        if len(things) > 0:
            _log.info(f"Parsed {len(things)} things from hostname!")
        else:
            _log.info(f"Nothing was parsed from this hostname!")
        # _log.info(f"raw: {raw}")
        # _log.info(f"api_config: {api_conf.to_dict()}")
        return things

    def parse_ip(
        self,
        raw: dict = {},
        api_conf: APIConfig = None,
        check_dates: Optional[bool]=False,
    ):
        _log = self.logger
        things = []

        # handle check_dates to potentially avoid re-parsing something that's
        # already been cached and parsed.
        last_seen = None
        last_seen_attr = None
        if 'results' in raw and raw['results']:
            for res in raw['results']:
                if 'last_seen' in res and res['last_seen']:
                    dto = self._format_date(res['last_seen'])
                    if not last_seen or dto > last_seen:
                        last_seen = dto
            if check_dates:
                if last_seen in check_dates:
                    return last_seen
                else:
                    return False
            last_seen_attr = Attribute(label='date-seen', value=last_seen)
            things.append(last_seen_attr)
        if check_dates:
            return False

        # Parse results if we're dealing with new records/uncached data
        if 'results' in raw and raw['results']:
            data = raw['results']
            counter = 0
            for res in data:
                dkas = {
                    'date': 'date-seen',
                    'qname': 'fqdn',
                    'value': 'dns-value',
                    'type': 'dns-type',
                    'value_ip': 'ip-address',
                }
                has = []
                resolves = []
                related = []

                date_attr = None
                if 'last_seen' in res:
                    date_attr = Attribute(
                        label='date-seen',
                        value=self._format_date(res['last_seen'])
                    )
                    # has.append(date_attr)

                dom = None
                if 'domain' in res and res['domain']:
                    dom = Attribute(label='domain-name', value=res['domain'])
                    domain = Entity(label='domain', has=[dom])
                    if date_attr:
                        domain.has.append(date_attr)
                    resolves.append(domain)

                    if 'qname' in res:
                        if res['qname'].endswith(f".{res['domain']}"):
                            fqdn = Attribute(label='fqdn', value=res['qname'])
                            hostname = Entity(label='hostname', has=[fqdn])
                            if date_attr:
                                hostname.has.append(date_attr)
                            resolves.append(hostname)

                if 'value_ip' in res and res['value_ip']:
                    ipaddy = Attribute(label='ip-address', value=res['value_ip'])
                    ip = Entity(label='ip', has=[ipaddy])
                    if date_attr:
                        ip.has.append(date_attr)
                    resolves.append(ip)

                reso_rel = self._generate_relation_from_data(
                    data = res,
                    datakey_attrlbls=dkas,
                    label = 'resolution',
                    has=has,
                    players = {},
                )
                # Make sure all dns-values are strings
                for attr in reso_rel.has:
                    if not attr:
                        continue
                    if not isinstance(attr.value, str):
                        attr._value=str(attr.value)
                if resolves:
                    reso_rel.players['resolves'] = resolves
                if related:
                    reso_rel.players['related'] = related

                things.append(reso_rel)
        if len(things) > 0:
            _log.info(f"Parsed {len(things)} things from hostname!")
        else:
            _log.info(f"Nothing was parsed from this hostname!")

        return things

    def parse_d8s(
        self,
        raw: dict = {},
        api_conf: APIConfig = None,
        check_dates: Optional[bool]=False,
    ):
        """d8s parsing

        d8s data from zetalytics is an attempt to parse WHOIS data returned from
        live WHOIS lookups.

        NOTE: At the time of this writing, this parsing function is ONLY designed
        to handle a single response (i.e. size=1 in the request). THIS WILL
        PROBABLY BREAK IF YOU SEARCH FOR HISTORICAL D8S DATA AND GET MORE THAN
        ONE RESPONSE!

        I imagine it'll have to account for result lists in the case of historical
        responses, but haven't found a use-case for that yet, so I'm not
        messing with it today.

        :returns dict: returns dict of {'raw': <JSON>,  'things': [<parsed_things]}
        """

        _log = self.logger
        things = []

        # handle check_dates to potentially avoid re-parsing something that's
        # already been cached and parsed.
        last_seen = None
        last_seen_attr = None
        results = None
        if 'results' in raw and raw['results']:
            # for res in raw['results']:
            results = raw['results']
            if 'ts' in results and results['ts']:
                dto = self._format_date(results['ts'])
                if not last_seen or dto > last_seen:
                    last_seen = dto
            else:
                _log.info(f"No valid timestamp returned! Likely invalid domain: {raw}")
                return things
            if check_dates:
                if last_seen in check_dates:
                    return last_seen
                else:
                    return False
            last_seen_attr = Attribute(label='date-seen', value=last_seen)
            things.append(last_seen_attr)
        else:
            _log.info(f"No valid d8s results returned!: {raw}")
            return things

        if check_dates:
            return False

        # Parse results if we're dealing with new records/uncached data
        data = None
        if 'response' in results and results['response']:
            data = results['response']
        else:
            _log.info(f"No d8s 'response' data returned: {raw}")
            return []

        dkas = {
            'd': 'domain-name',
            'c': 'created-date',
            'e': 'expires-date',
            'r': 'registrar',
            # 'o': 'last-name', # keep it simple for now - no need to collect
            #    a bunch of anonymized email addys/names
            'n': 'name-server',
        }
        has = [last_seen_attr]
        resolves = []
        related = []

        whois_ent = self._generate_entity_from_data(
            data = data,
            datakey_attrlbls=dkas,
            label = 'whois',
            has=has,
        )

        # make sure all attribute values are strings
        # eh.... but what about dates? Is this a bug from the previous routine?
        '''
        for attr in whois_ent.has:
            if not attr:
                continue
            if not isinstance(attr.value, str):
                attr._value=str(attr.value)
        '''

        things.append(whois_ent)

        # insert pointless info message if you must
        while None in things:
            things.remove(None)
        return things


    #################################################
    ### hunt or Kill Logical Functions
    #################################################

    def hok_hostname(
        self,
        dbc: ConnectorPlugin = None,
        thing: Relation = None,
    ):
        """hunt-or-kill Hostname logic
        Runs checks to determine if Hostname enrichment should be hunted or
        killed based on recent events related to that enrichment.

        When triggered, call self.hok_trigger(dbc, thing, trigger_reason)
        from HNTRPlugin.

        **Logic**:
            - If the enrichment itself is marked False-Positive, trigger hok.
            - If no IPs are associated with this enrichment yet, pass.
            - If a new IP is found that, trigger HOK. (if IP date-discovered is
                > trigger_date (which is either the date the enrichment was
                discovered, or the date a 'continue hunting' decision was made,
                whichever is later.))
            - If no new IP has been discovered for 45 days, trigger HOK.

        :param dbc: Database ConnectorPlugin for checking logic
        :param thing: The enrichment we're determining to hunt or kill
        :returns: True if HOK-logic was triggered, otherwise False.
        """
        _log = self.logger
        trigger_date = self.get_trigger_date(thing=thing)
        # Check for FP
        con = thing.get_attributes('confidence', first_only=True)
        if con and con.value < 0:
            reason = f"low confidence"
            self.hok_trigger(
                dbc=dbc,
                thing=thing,
                trigger_reason=reason,
            )
            return True
        # Check for new IPs
        new_ip_count = 0
        last_discovery = None
        for player in thing.players['found']:
            if player.label=='ip':
                attr = player.get_attributes(
                    'date-discovered',
                    first_only=True
                )
                dd = attr.value.replace(tzinfo=timezone.utc)
                date_discovered = datetime(dd.year, dd.month, dd.day, tzinfo=timezone.utc)
                if not last_discovery or date_discovered > last_discovery:
                    last_discovery = date_discovered
                if date_discovered > trigger_date:
                    new_ip_count+=1
        if new_ip_count > 1:
            reason = f"discovered {new_ip_count} new IPs"
            self.hok_trigger(
                dbc=dbc,
                thing=thing,
                trigger_reason=reason,
            )
            return True
        else:
            _log.debug(f"hok_hostname IP count passed")
            _log.debug(f"Only discovered {new_ip_count} new IPs since {trigger_date}")
        now = datetime.now(timezone.utc)
        days_passed = now-last_discovery
        if days_passed.days >= 45:
            reason = f"no new discoveries in {days_passed.days} days"
            self.hok_trigger(
                dbc=dbc,
                thing=thing,
                trigger_reason=reason,
            )
            return True
        else:
            _log.debug(f"hok_hostname freshness check passed")
            _log.debug(f"Discovered most recent IP {days_passed.days} days ago!")
            _log.debug(f"last_discovery: {last_discovery}")
            _log.debug(f"days_passed: {days_passed}")
        return False

    def hok_ip(
        self,
        dbc: ConnectorPlugin = None,
        thing: Relation = None,
    ):
        """hunt-or-kill IP logic
        Runs checks to determine if IP enrichment should be hunted or
        killed based on recent events related to that enrichment.

        **Logic**:
            - If the enrichment itself is marked False-Positive, trigger hok.
            - If no Domains are associated with this enrichment yet, pass.
            - If >= 5 Domains associated with this IP since the trigger date,
                trigger HOK.
            - If no new discoveries were found in 45 days, trigger.

        :param dbc: Database ConnectorPlugin for checking logic
        :param thing: The enrichment we're determining to hunt or kill
        :returns: True if HOK-logic was triggered, otherwise False.
        """
        _log = self.logger
        trigger_date = self.get_trigger_date(thing=thing)
        # Check for FP
        con = thing.get_attributes('confidence', first_only=True)
        if con and con.value < 0:
            reason = f"low confidence"
            self.hok_trigger(
                dbc=dbc,
                thing=thing,
                trigger_reason=reason,
            )
            return True
        # Check for new domains
        new_dom_count = 0
        last_discovery = None
        for player in thing.players['found']:
            if player.label=='domain':
                attr = player.get_attributes(
                    'date-discovered',
                    first_only=True
                )
                dd = attr.value.replace(tzinfo=timezone.utc)
                date_discovered = datetime(dd.year, dd.month, dd.day, tzinfo=timezone.utc)
                if not last_discovery or date_discovered > last_discovery:
                    last_discovery = date_discovered
                if date_discovered > trigger_date:
                    new_dom_count+=1
        if new_dom_count >= 5:
            reason = f"discovered {new_dom_count} new domains"
            self.hok_trigger(
                dbc=dbc,
                thing=thing,
                trigger_reason=reason,
            )
            return True
        else:
            _log.debug(f"hok_ip Domain count passed")
            _log.debug(f"Only discovered {new_dom_count} new domains since {trigger_date}")
        now = datetime.now(timezone.utc)
        days_passed = now-last_discovery
        if days_passed.days >= 45:
            reason = f"no new discoveries in {days_passed.days} days"
            self.hok_trigger(
                dbc=dbc,
                thing=thing,
                trigger_reason=reason,
            )
            return True
        else:
            _log.debug(f"hok_ip freshness check passed")
            _log.debug(f"Discovered most recent domain {days_passed.days} days ago!")
            _log.debug(f"last_discovery: {last_discovery}")
            _log.debug(f"days_passed: {days_passed}")
        return False

    #################################################
    ### TODO
    #################################################

    def parse_domain2whois(
        self,
        raw: dict = {},
        api_conf: APIConfig = None,
        check_dates: Optional[bool]=False,
    ):
        _log = self.logger
        things = []

        return things

    def parse_subdomains(
        self,
        raw: dict = {},
        api_conf: APIConfig = None,
        check_dates: Optional[bool]=False,
    ):
        _log = self.logger
        things = []

        return things

    #################################################
    ### hunt or Kill Logical Functions
    #################################################

    def hok_subdomains(
        self,
        thing: Relation = None,
    ):
        """hunt-or-kill Subdomains logic
        Runs checks to determine if Subdomains enrichment should be hunted or
        killed based on recent events related to that enrichment.

        **Logic**:
            - If the last result was > 30 days ago, trigger HOK.

        :param thing: The enrichment we're determining to hunt or kill
        :returns: True if HOK-logic was triggered, otherwise False.
        """
        _log = self.logger
        return False

    def hok_d8s(
        self,
        thing: Relation = None,
    ):
        """hunt-or-kill d8s (WHOIS) logic
        Runs checks to determine if d8s/WHOIS enrichment should be hunted or
        killed based on recent events related to that enrichment.

        ...this is disabled for auto-hunt after its initial run, so we may never
        even use this.

        **Logic**:
            - [TBD] If the last result was > 30 days ago, trigger HOK.

        :param thing: The enrichment we're determining to hunt or kill
        :returns: True if HOK-logic was triggered, otherwise False.
        """
        _log = self.logger
        return False