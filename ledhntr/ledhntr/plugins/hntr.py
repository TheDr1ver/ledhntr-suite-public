import copy
import dateutil.parser
import json
import logging
import os
import re
import requests

from typing import Dict, Optional
from abc import abstractmethod, ABC
from configparser import ConfigParser
from datetime import datetime, timezone
from pprint import pformat
from time import time, sleep

from ledhntr.data_classes import Attribute, Entity, Relation, Thing
from ledhntr.plugins import BasePlugin
from ledhntr.plugins.connector import ConnectorPlugin
from ledhntr.helpers import LEDConfigParser, format_date, flatten_dict


from typing import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
    Union,
)

class APIConfig():
    def __init__(
        self,
        endpoint: str = "",
        uri: str = "",
        params: Dict = {},
        parser: Any = None,
        add_to_db: Any = None,
        simple_query_types: Optional[Union[List, str]] = [],
        param_query_key: Optional[str] = "",
        frequency: Optional[int] = None,
        auth: Optional[str] = None,
        headers: Optional[Dict] = {},
        http_method: Optional[Any] = requests.get,
        hunt_active: Optional[bool] = True,
        hunt_name: Optional[str] = "",
        hok_logic: Optional[Any] = None,
    ) -> None:
        """ Configuration object that holds the details of each endpoint

        :param add_to_db: Function used for adding the results of the endpoint
            to the database (e.g. self.add_hunt)
        :param endpoint: Name of endpoint as referenced by hunt/enrich objects
        :param params: Dictionary of explicit API parameters. Example:
            {
                'query': {
                    'value: '',
                    'form_input': 'textbox',
                    'type': str,
                }
            }
        :param parser: Function used for parsing the API response. This function
            should take the raw response + this APIConfig object for any potential
            parsing requirements that might happen inside the parser.
        :param uri: URI used for hitting endpoint. Format-aware. Example:
            "/shodan/host/{query}"
        :param param_query_key: Primary parameter query key.
            NOTE - Scenarios for what to set this as:
            - If there is no query field in the request (e.g. account_status),
                this should be set to `None`
            - If it's expecting a query parameter in either the .params section
                or in the URI itself, this should be set to `self.param_query_key`
            - If the endpoint expects a non-default param as its primary key,
                this should be set as the string representation of that key.
            - If the endpoint requires any one of multiple potential params, this
                should be set to the tuple interpretation of those params
                (e.g. param_query_key=("uuid", "url"))
        :param simple_query_types: List of entities that can be queried against this
            endpoint simply by adding its keyval to the query line. For example,
            VirusTotal could probably do a generic search for ['ip', 'domain', 'file']
        :param frequency: Default frequency for which this API endpoint should be
            regularly checked.
        :param auth: Basic Auth string.
        :param headers: Certain APIs require explicit headers.
        :param http_method: Defaults to requests.get(). Can be changed to POST,
            PATCH, OPTIONS, etc. as-needed.
        :param hunt_active: Whether or not the hunt will be activated after
            its first run.
        :param hunt_name: A format-capable string (e.g. "hosts_{query}") so that
            we can later call hunt_name.format(query) and get teh proper hunt_name.
        :param hok_logic: Plugin-specific hunt-or-kill logic function
            used to determine if an automated enrichment should be suspended
            when specific events occur.

            When a specific set of factors are triggered, this function
            should set its corresponding hunt_active boolean to False, and
            apply the tag `hunt-or-kill`, which effectively requires a
            human to enter the loop. Additionally, a `note` may be added to
            hint at the reason towards  the `hok` logic being triggered.
            (e.g. `hok:2022-09-26:new ip found:192.168.1.100`)

            If the hunt is determined to be `hunted` (e.g.
            keep autohunting), the `hunt-or-kill` tag will be removed,
            and a `note` of `hunted:2022-09-26` will be added to the hunt.

            Alternatively, if the hunt is determined to no longer be of use
            and the `kill` option is chosen, a `note` of `killed:2022-09-26`
            will be added to the hunt.

            If the set of logical factors are triggered again, the same
            process will repeat.

        TODO - Add API endpoint description and a function to HNTRPlugin()
            that lists all loaded APIConfigs, their function, and their
            primary query key + params
        """
        self.add_to_db = add_to_db
        self.endpoint = endpoint
        self.params = params
        self.parser = parser
        self.uri = uri
        self.param_query_key = param_query_key
        self.simple_query_types = simple_query_types
        self.frequency = frequency
        self.auth = auth
        self.headers = headers
        self.http_method = http_method
        self.hunt_active = hunt_active
        self.hunt_name = hunt_name
        self.hok_logic = hok_logic

    def get_query(
        self,
        param_query_key: str = "",
    ):
        return self.params.get(param_query_key)

    def to_dict(self):
        return self.__dict__

    def __repr__(self) -> str:
        if self.endpoint:
            s = f"<{self.__class__.__name__}({self.endpoint})"
        else:
            s = f"<{self.__class__.__name__}(NotInitialized)"
        return s

class HNTRPlugin(BasePlugin, ABC):
    def __init__(
        self,
        config:LEDConfigParser,
        logger: Optional[object] = None,
    ) -> None:
        super().__init__(config)
        if not logger:
            self.logger: logging.Logger = logging.getLogger('ledhntr')
        else:
            self.logger = logger
        _log = self.logger

        # API call counter - one key for 'total' and one key per endpoint
        self.api_calls = {}
        # Used for checking rate limits
        self.search_time = 0
        # Universal tags to be ignored when processing enrichments
        self.enrich_ignore_tags = [
            'censys-scanner',
            'shodan-scanner',
            'scanner',
            'no-pivot',
        ]

    def _set_request_args(
        self,
        api_conf: APIConfig = None,
    ):
        """Pull request args from APIConfig and set them for their HTTP request.

        :param api_conf: APIConfig object to pull configurations from

        :returns: Dict of request arguments
        """

        _log = self.logger
        reqkwargs = {}
        if not self.base_url.endswith('/'):
            self.base_url += "/"
        try:
            # Build URL
            reqkwargs['url'] = f"{self.base_url}{api_conf.uri}"
            # Build Headers
            if api_conf.headers:
                reqkwargs['headers'] = api_conf.headers
            # Build Params
            reqkwargs['params'] = {}
            ogac = self.api_confs.get(api_conf.endpoint)
            ogparams = ogac.params
            for param, val in api_conf.params.items():
                # If the parameter isn't in the original APIConfig params, then
                # it's not an official parameter and shouldn't be passed to
                # requests as a param. This is largely so we don't send
                # unnecessary queries to API endpoints that have the query
                # as part of the URI instead of as a param.
                if param not in ogparams:
                    continue
                if callable(val):
                    reqkwargs['params'][param] = val()
                elif not val is None:
                    # reqkwargs['params'][param] = requests.utils.quote(val, safe='')
                    reqkwargs['params'][param] = val
            # Check for Auth
            if hasattr(api_conf, 'auth') and api_conf.auth:
                reqkwargs['auth'] =api_conf.auth
            # Check for proxies
            if hasattr(self, 'http_proxy') or hasattr(self, 'https_proxy'):
                proxies = {}
                if hasattr(self, 'http_proxy') and self.http_proxy:
                    proxies['http'] = self.http_proxy
                if hasattr(self, 'https_proxy') and self.http_proxy:
                    proxies['https'] = self.https_proxy
                if proxies:
                    reqkwargs['proxies'] = proxies
            # Check ssl_verify
            if hasattr(self, 'ssl_verify'):
                if self.ssl_verify == False:
                    reqkwargs['verify'] = False

        except Exception as e:
            _log.error(f"Failed setting request arguments: {e}")
            pass
        return reqkwargs

    def _fire_api(
        self,
        api_conf: APIConfig = None,
        reqkwargs: dict = {},
        token_refreshed: Optional[bool] = False,
    ):
        """Fire LIVE API request down range
        Sends an API request to the server based on the configs in api_conf and
            the requests-specific arguments passed by reqkwargs. If response
            status starts with 2*, success is assumed, and the response is parsed
            and returned.

        :param api_conf: APIConfig for this API endpoint
        :param reqkwargs: Requests-specific arguments set by _set_request_args()
            and any manual updates a function may have made before passing it
            to _fire_api().

        :returns: Parsed JSON response if successfully parsed. Text response if
            2* status_code and unsuccessful JSON parsing. Result object if
            unsuccessful.
        """
        _log = self.logger
        data = False

        self.rate_limit_respect(self.search_time, self.rate_limit)
        self.search_time = time()
        res = api_conf.http_method(**reqkwargs)
        if not str(res.status_code).startswith('2'):
            _log.error(
                f"Error obtaining reports: [{res.status_code}] - {res.text}"
            )
            return res
        try:
            data = res.json()
        except Exception as e:
            _log.error(f"Could not parse response JSON: {e}")
            data = res.text
        return data

    def _con_threshold_check(
        self,
        dbc: ConnectorPlugin = None,
        thing: Thing = None,
        con_threshold: float = None,
    ):
        """Check confidence threshold of a thing and its parents
        Given a Thing, check to see that it meets the threshold requirements
        that would allow it to become an automatic pivot.

        :param dbc: ConnectorPlugin to the database
        :param thing: Thing to check confidence threshold against
        :param con_threshold: Threshold for which this Thing is considered
            high-fidelity enough to pivot on.

        :returns: True/False with regards to whether or not Thing should
            be ignored. True means SKIP THING!

        """
        _log = self.logger
        if not dbc:
            _log.error(f"Invalid database connector: {dbc}")
            return True
        if not thing:
            _log.error(f"No thing to compare!")
            return True
        if not con_threshold:
            _log.error(
                f"No confidence threshold provided for comparison! {con_threshold}"
            )
            return True

        ignore_me = False
        con_low = False
        for attr in thing.has:
            if attr.label=='confidence':
                if attr.value < con_threshold:
                    con_low = True
                # If confidence is explicitly a false-positive, return True
                # We don't want to create pivots on any domains that we explicitly
                # don't care about
                if attr.value < 0:
                    return True
        if not con_low:
            # confidence threshold met! Do not skip this thing!
            return ignore_me

        _log.debug(f"Initial Entity confidence low. Checking parent hunts.")
        if not thing.relations:
            thing = dbc.find_things(
                thing,
                search_mode='no_backtrace'
            )[0]
        thing_parent_acceptable = False
        for rel in thing.relations:
            # Only look at enrichments and hunts...
            if not (rel.label=='enrichment' or rel.label=='hunt'):
                continue

            # Make sure this hunt/enrichment has an acceptable confidence
            sub_con_low = False
            for attr in rel.has:
                if attr.label == 'hunt-active':
                    if attr.value == False:
                        # If a hunt is inactive, it can't be used as an authority.
                        sub_con_low = True
                        break
                if attr.label=='confidence':
                    if attr.value < self.con_threshold:
                        sub_con_low = True
                        break
            if sub_con_low:
                continue

            # If we passed those checks, get all findings of this hunt/enrichment...
            half_rel = dbc.find_things(
                rel,
                search_mode='no_backtrace'
            )[0]

            # Make sure this hunt/enrich found something
            if not 'found' in half_rel.players:
                continue

            # Make sure our Thing was a finding of this enrichment
            for found_thing in half_rel.players['found']:
                if found_thing.iid == thing.iid:
                    thing_parent_acceptable = True
                    break

            if thing_parent_acceptable:
                # If we found an acceptable parent, stop looping through rels
                _log.info(
                    f"Found related parent with acceptable confidence: "
                    f"{half_rel}"
                )
                _log.info(f"{thing} deemed 'good enough' to enrich")
                break

        if not thing_parent_acceptable:
            ignore_me = True
        return ignore_me

    def _walk_data(
        self,
        data: Union[Dict, List]={},
        dkl: List[str] = [],
        attrlabel: str='',
        counter: int = 1,
        logger: Optional[object] = None,
    ):
        if logger:
            _log = logger
        else:
            _log = self.logger
        attrs = []
        # returns attrs

        if not isinstance(data, list):
            data = [data]

        for di in data:
            if len(dkl) == counter:
                datakey = dkl[counter-1]
                if datakey in di:
                    # dkcombo = ';;;'.join(dkl)
                    # attrlabel = datakey_attrlbls[dkcombo]
                    val = di[datakey]
                    if not isinstance(val, list):
                        val = [val]
                    for v in val:
                        # something about the attrlabel=='date-seen' feels hacky
                        # and I don't like it. But for now it's better than checking
                        # to see if v is a string that can be converted succesfully
                        # to a datetime object first
                        if isinstance(v, datetime) or attrlabel=='date-seen':
                            v = self._format_date(v)
                        attr = Attribute(
                            label=attrlabel,
                            value = v,
                        )
                        if attr not in attrs:
                            attrs.append(attr)
                    # return attrs
            else:
                datakey = dkl[counter-1]
                if datakey in di:
                    counter += 1
                    updated_data = di[datakey]
                    attrs_res = self._walk_data(
                        data=updated_data,
                        dkl=dkl,
                        # datakey_attrlbls=datakey_attrlbls,
                        attrlabel=attrlabel,
                        counter=counter
                    )
                    for attr in attrs_res:
                        if attr not in attrs:
                            attrs.append(attr)
                else:
                    _log.error(f"Something wrong... {datakey} not in {di}")
                    d = {
                        'data': di,
                        'dkl': dkl,
                        'attrlabel': attrlabel,
                        'counter': counter
                    }
                    _log.error(pformat(d))
        return attrs

    def _add_data_as_attribute_new(
        self,
        data: Dict = {},
        datakey_attrlbls: Dict[str,str] = [],
        has: Optional[List[Attribute]] = [],
    ):
        """
        Given a data dictionary and list of {datakey, attrlbl} kv pairs,
        convert the data dictionary into an attribute.

        (e.g.
            dummy_data = {
                'services': [{
                    'service_name': 'ssh',
                    'software': [
                        {'other': {'comment': 'Ubuntu-4ubuntu0.5'},
                            'product': 'openssh',
                            'source': 'OSI_APPLICATION_LAYER'},
                        {'part': 'o',
                            'product': 'linux',
                            'source': 'OSI_TRANSPORT_LAYER',
                            'uniform_resource_identifier': 'cpe:2.3:o:*:linux:*:*:*:*:*:*:*:*'},
                    ]
                }]
            }

            data = dummy_data['services']

            dka = {
                'service_name': 'service-name',
                'software;;;product': 'product',
                'software;;;source': 'source',
            }
        )

        :param data: Dictionary containing k/v pairs we want to convert to
            Attribute Thing objects
        :param datakey_attrlbls: Dict where datakey is keys in data
            and attrlbl is a valid Attribute label from the schema
        :param attributes: List of existing attributes we may want to append to

        """
        _log = self.logger
        for datakey, attrlabel in datakey_attrlbls.items():
            dkl = datakey.split(';;;')
            attrs = self._walk_data(data=data, dkl=dkl, attrlabel=attrlabel)
            for attr in attrs:
                if attr not in has:
                    has.append(attr)
        return has

    def _add_data_as_attribute(
        self,
        data: Dict = {},
        datakey_attrlbls: Dict[str,str] = [],
        has: Optional[List[Attribute]] = [],
    ):
        """
        Given a data dictionary and list of {datakey, attrlbl} kv pairs,
        convert the data dictionary into an attribute.

        (e.g.
            data = {'country_code': 'US', 'city': 'Baltimore', 'province': 'MD'}
            datakey_attrlbls = [
                {'country_code': 'country-code'},
                {'city': 'city'},
                {'province': 'province'}
            ]
        )

        :param data: Dictionary containing k/v pairs we want to convert to
            Attribute Thing objects
        :param datakey_attrlbls: Dict where datakey is keys in data
            and attrlbl is a valid Attribute label from the schema
        :param attributes: List of existing attributes we may want to append to

        """
        _log = self.logger
        has = has
        for datakey, attrlabel in datakey_attrlbls.items():
            if datakey in data:
                val = data[datakey]
                if not isinstance(val, list):
                    val = [val]
                for v in val:
                    if not v:
                        # Account for null values
                        continue
                    # something about the attrlabel=='date-seen' feels hacky
                    # and I don't like it. But for now it's better than checking
                    # to see if v is a string that can be converted succesfully
                    # to a datetime object first
                    if isinstance(v, datetime) or attrlabel=='date-seen':
                        try:
                            v = self._format_date(v)
                        except Exception as e:
                            _log.error(f"Error parsing date: {e}")
                            _log.error(f"value = {v} type: {type(v)}")
                            _log.error(f"attrlabel = {attrlabel}")
                            _log.error(f"datakey = {datakey}")
                            _log.error(f"datakey_attrlbls: {pformat(datakey_attrlbls)}")
                            raise
                    attr = Attribute(
                        label=attrlabel,
                        value = v,
                    )
                    if not isinstance(attr, Attribute):
                        _log.error(
                            f"Passed value {attr} is NOT an Attribute! Adding as note."
                        )
                        attr = Attribute(label='note', value=str(attr))
                    if attr not in has:
                        has.append(attr)
        return has

    def _find_active_hunts(
        self,
        dbc: ConnectorPlugin = None,
        ignore_freq: bool = False,
        iid: Optional[str] = '',
    ):
        """
        Finds all active "huntable" objects for the service. The following
        requirements must be met in order for it to be passed on to the next
        step:

            - Have hunt-active == True
            - Have a hunt-endpoint
            - Have a hunt-string
            - Have a hunt-name
            - Have hunt-service == '{Your_Plugin}'
            - Have a last-seen OLDER/LESS THAN than (now()-(frequency*60*60))

        iid is optional, but if provided, explicitly looks for a given IID
        """

        _log = self.logger

        all_active_hunts = []
        last_seen = False

        # Create search object
        active = Attribute(label='hunt-active', value=True)
        endpoint = Attribute(label='hunt-endpoint')
        string = Attribute(label='hunt-string')
        service = Attribute(
            label='hunt-service',
            value=self.__class__.__name__
        )
        search_object = Relation(
            label="hunt",
            has = [active, service, endpoint, string]
        )

        if iid:
            search_object.iid=iid

        # Search for objects matching above criteria
        all_hunts = dbc.find_things(
            search_object,
            limit_get=True,
            search_mode="lite",
            include_meta_attrs=True,
        )

        # if not isinstance(all_hunts, list):
        #     all_hunts = [all_hunts]

        # Confirm everything we got back is what we expected
        for hunt in all_hunts:
            safe_copy = copy.deepcopy(hunt.has)
            # for attr in hunt.has:
            skip_me = False
            for attr in safe_copy:
                if attr.label == 'hunt-active':
                    if not attr.value == True:
                        skip_me = True
                        break
                if attr.label == 'hunt-endpoint':
                    if not attr.value:
                        _log.warning(
                            f"Hunt {hunt.iid} has no endpoint! Skipping."
                        )
                        skip_me = True
                        break
                    hunt_endpoint = attr.value
                    hunt_endpoint = hunt_endpoint.strip('/')
                if attr.label == 'hunt-string':
                    if not attr.value:
                        _log.warning(
                            f"Hunt {hunt.iid} has no hunt-string! Skipping."
                        )
                        skip_me = True
                        break
                    # Convert escapes back to regular seach strings
                    hunt_string = attr.value
                    unescaped = hunt_string.replace("\\\"", "\"")
                    new_attr = Attribute(iid=attr.iid, label=attr.label, value=unescaped)
                    hunt.has.remove(attr)
                    hunt.has.append(new_attr)
                if attr.label == 'hunt-service':
                    if not attr.value == self.__class__.__name__:
                        _log.warning(
                            f"Hunt {hunt.iid} is for {attr.value}! Skipping."
                        )
                        skip_me = True
                        break
                if attr.label == 'frequency':
                    frequency = attr.value
                if attr.label == 'last-seen':
                    last_seen_attr = attr
                    last_seen = int(attr.value.timestamp())

            if last_seen:
                now = int(datetime.now().timestamp())
                mintime = last_seen+(frequency*60*60)
                if now < mintime:
                    _log.info(
                        f"Hunt {hunt.iid} has not cooled off enough. "
                        f"Last run was {datetime.fromtimestamp(last_seen)} "
                        f" now needed to be {datetime.fromtimestamp(mintime)} "
                        " or later!"
                    )
                    if not ignore_freq:
                        skip_me = True
                    else:
                        _log.info("...but who cares?!")
                else:
                    _log.info(
                        f"Hunt {hunt.iid} is ready for go-time! "
                        f"It last ran {datetime.fromtimestamp(last_seen)} "
                        f"now needed to be {datetime.fromtimestamp(mintime)} "
                        f" or later!"
                    )
                # We'll try scrapping adding a date-seen for every time this is run
                # as well. That way you don't end up with last_seen being the last time
                # this was run even though the results haven't updated.
                # dto = datetime.now(timezone.utc)
                # date_seen = Attribute(label='date-seen', value=dto)
                # _log.info(f"Adding new date-seen to hunt...")
                # dbc.attach_attribute(hunt, date_seen)

                # Shouldn't update last_seen until the timestamp updater handles it
                # new_last_seen = Attribute(label='last-seen', value=dto)
                # dbc.detach_attribute(hunt, last_seen_attr)
                # dbc.attach_attribute(hunt, new_last_seen)

            if skip_me:
                continue
            _log.info(f"Pulling down players for {hunt}...")
            hunt = dbc.find_things(hunt, search_mode='no_backtrace')[0]
            _log.info(f"Added!")
            all_active_hunts.append(hunt)

        return all_active_hunts

    def _gen_enrich_map(
        self,
        dbc: ConnectorPlugin = None,
        schema: Optional[str] = "",
    ):
        """Generate enrichment map based on schema and APIConfig objects.

        The enrichment map will then be used for determining which types of
        entities are allowed to be auto-hunted on with which types of endpoints.

        :param dbc: Database connector that will be used to parse the schema file
        :para schema: Location of schema file. If none provided, defaults to
            ledhntr schema.tql

        :returns: Inherently it sets self.enrich_map, but also returns a dict
            containing the enrichment map.
        """
        _log = self.logger
        if not dbc:
            _log.error(f"Database connector required to generate enrichment map!")
            return {}

        '''
        self.enrich_map = {
            'ip': {
                'endpoints': [
                    'zeta_ip',
                ],
                'key': 'ip-address',
            },
            'domain': {
                'endpoints': [
                    'zeta_hostname',
                    'zeta_subdomains',
                    'zeta_domain2whois',
                ],
                'key': 'domain-name',
            },
            'hostname':{
                'endpoints': [
                    'zeta_hostname',
                    'zeta_subdomains',
                    'zeta_domain2whois',
                ],
                'key': 'fqdn',
            },
        }
        '''
        schema_things = dbc.parse_schema_file(schema=schema)
        self.enrich_map = {}

        if not hasattr(self, 'api_confs'):
            _log.info(f"{self} has no api_confs set!")
            return self.enrich_map

        for endpoint, ac in self.api_confs.items():
            if not ac.simple_query_types:
                continue
            for ent_label in ac.simple_query_types:
                # Find ent keyattr
                for _, things in schema_things.items():
                    keyattr = None
                    for thing in things:
                        if thing.label==ent_label:
                            keyattr = thing.keyattr
                            break
                    if keyattr:
                        break

                # populate enrich_map
                if ent_label not in self.enrich_map:
                    self.enrich_map[ent_label] = {
                        'endpoints': [ac.endpoint],
                        'key': keyattr
                    }
                else:
                    self.enrich_map[ent_label]['endpoints'].append(ac.endpoint)

        return self.enrich_map

    def _generate_entity_from_data(
        self,
        data: Dict = {},
        datakey_attrlbls: Dict[str,str] = [],
        has: Optional[List[Attribute]] = [],
        label: Optional[str] = '',
        entity: Optional[Entity] = None,
    ):
        """
        Returns a single Entity Thing Object with additional attribtues after
        utilizing the _add_data_as_attribute function.

        :param data: Dictionary containing k/v pairs we want to convert to
            Attribute Thing objects
        :param datakey_attrlbls: Dict where datakey is keys in data
            and attrlbl is a valid Attribute label from the schema
        :param label: If creating a brand new entity, its label is required
        :param has: List of existing attributes we may want to append to
        :param entity: Existing entity we'd like to add more attributes to

        """
        _log = self.logger
        if not entity:
            if not label:
                _log.error(
                    f"Cannot generate entity without preexisting Entity or Label!"
                )
                return False
            entity = Entity(label=label, has=has)

        # has = self._add_data_as_attribute(
        # has = self._add_data_as_attribute_new(
        parsed_attrs = self._add_data_as_attribute(
            data=data,
            datakey_attrlbls=datakey_attrlbls,
            has=has
        )
        for attr in parsed_attrs:
            if isinstance(attr, Attribute) and attr not in entity.has:
                entity.has.append(attr)
        # _log.debug(f"Generated entity: {entity.to_dict()}")
        return entity

    def _generate_relation_from_data(
        self,
        data: Dict = {},
        datakey_attrlbls: Dict[str,str] = [],
        has: Optional[List[Attribute]] = [],
        label: Optional[str] = '',
        players: Optional[Dict[str, List[Entity]]] = None,
        relation: Optional[Relation] = None,
    ):
        """
        Returns a single Relation Thing Object with additional attribtues after
        utilizing the _add_data_as_attribute function.

        :param data: Dictionary containing k/v pairs we want to convert to
            Attribute Thing objects
        :param datakey_attrlbls: Dict where datakey is keys in data
            and attrlbl is a valid Attribute label from the schema
        :param label: If creating a brand new entity, its label is required
        :param has: List of existing attributes we may want to append to
        :param players: Dict[str,List[Entity]] - Players and their roles associated
            with this Relation Thing Object
        :param relation: Existing Relation we'd like to add more attributes to

        """
        _log = self.logger
        if not relation:
            if not label:
                _log.error(
                    f"Cannot generate entity without preexisting Relation or Label!"
                )
                return False
            relation = Relation(label=label, has=has, players=players)

        # has = self._add_data_as_attribute(
        # has = self._add_data_as_attribute_new(
        _log.debug(f"Generating relation (before parsing attrs): {relation.to_dict()}")
        parsed_attrs = self._add_data_as_attribute(
            data=data,
            datakey_attrlbls=datakey_attrlbls,
            has=has
        )

        for attr in parsed_attrs:
            if attr not in relation.has:
                relation.has.append(attr)

        return relation

    def _inc_api_counter(self, endpoint):
        _log = self.logger
        class_name = self.__class__.__name__
        if class_name not in self.api_calls:
            self.api_calls[class_name] = {'_total': 0}

        self.api_calls[class_name]['_total'] += 1
        if endpoint not in self.api_calls[class_name]:
            self.api_calls[class_name][endpoint] = 0
        self.api_calls[class_name][endpoint] += 1
        _log.info(
            f"Total {class_name} API calls:\n"
            f"{pformat(self.api_calls[class_name])}"
        )

    def _isa_date(
        self,
        date_string: str = "",
    ):
        # 8 because we'll assume the shortest possible date we want to deal
        # with is formatted like 20220611. Anything less than that we'll assume
        # is not a date.
        if len(date_string) < 8:
            return False
        try:
            date_string = dateutil.parser.parse(date_string)
            isa_date=True
        except Exception as ex:
            isa_date = False
        return isa_date

    def _format_date(
        self,
        date_string: Union[str,datetime] = "",
    ):
        dto = format_date(date_string)
        return dto

    def _set_confidence(
        self,
        things: List[Union[Entity, Relation]] = [],
    ):
        default_confidence = Attribute(label='confidence', value=0)
        for thing in things:
            if isinstance(thing, (Entity, Relation)):
                multi_con = thing.get_attributes('confidence')
                if len(multi_con) > 1:
                    for mc in multi_con:
                        if mc.value == 0.0:
                            thing.has.remove(mc)
                    self.logger.debug(f"Thing had {len(multi_con)} confidence levels!")
                    self.logger.debug(
                        f"New confidence levels: "
                        f"{thing.get_attributes('confidence')}"
                    )
                if multi_con:
                    continue
                thing.has.append(default_confidence)
        return things

    # HNTRPlugin functions called by scripts and other plugins

    def add_hunt(
        self,
        dbc: ConnectorPlugin = None,
        api_conf: Optional[APIConfig] = None,
        endpoint: Optional[str] = "",
        query: Optional[str] = "",
        hunt_active: Optional[bool] = True,
        hunt_name: Optional[str] = "",
        frequency: Optional[float] = None,
        confidence: Optional[float] = 0.0,
        add_as_enrichment: Optional[bool] = False,
        return_things: Optional[bool] = False,
        source_things: Optional[Union[List[Thing], Thing]] = None,
    ):
        """Adds a hunt to the database

        :param dbc: a database connector plugin used for writing objects to a database
        :param api_conf: APIConfig that generated the search/hunt. If None,
            endpoint and query are required.
        :param endpoint: Endpoint this hunt is directed towards. If not set,
            an endpoint from api_conf is required.
        :param query: String passed to the hunt. If none set, a query from
            api_conf is required.
        :param hunt_active: Determines whether or not the hunt is active for
            usage going forward.
        :param hunt_name: The name of the added hunt. If empty, a generic name
            will be auto-generated.
        :param frequency: Frequency with which the hunt is run.
        :param confidence: Confidence of new hunt - defaults to 0.0 or 'Unknown'
        :param add_as_enrichment: Whether or not the hunt is an explicit `hunt`
            type or if it's an `enrichment` type.
        :param return_things: Return the Hunt as a Thing object after added.
        :param source_things: Tie this hunt to a parent hunt (primarily for enrichments)

        :returns: added_hunt Relation object (if return_things == True)

        """
        _log = self.logger

        if not dbc:
            _log.error(f"Database connector required for adding hunt. dbc={dbc}")
            return False
        endpoint = endpoint or api_conf.endpoint
        if not endpoint.startswith(self.__class__.__name__.lower()):
            endpoint = f"{self.__class__.__name__.lower()}_{endpoint}"
        if not endpoint:
            _log.error(f"Endpoint required to add hunt. endpoint: {endpoint}")
            return False
        query = query or api_conf.get_query(self.param_query_key)
        if not query:
            _log.error(f"Query required to add hunt. query: {query}")
            return False
        frequency = frequency or api_conf.frequency
        if frequency is None:
            frequency = self.freq_threshold

        # since we're adding it for the first time, make sure it starts with
        # an initial date-seen
        now = datetime.now(timezone.utc)
        has = [
            Attribute(label='hunt-active', value=hunt_active),
            Attribute(label='hunt-service', value=self.__class__.__name__),
            Attribute(label='hunt-string', value=query),
            Attribute(label='hunt-endpoint', value=endpoint),
            Attribute(label='frequency', value=frequency),
            Attribute(label='date-seen', value=now),
            Attribute(label='confidence', value=confidence),
        ]

        # Generate a hunt_name if one is not provided
        if not hunt_name:
            dto = datetime.now()
            hunt_name = str(dto).replace(' ','T').replace('-','')
            hunt_name = hunt_name.replace(':','_').replace('.','_')        
        if not hunt_name.startswith(f"{self.__class__.__name__.lower()}-"):
            hunt_name = f"{self.__class__.__name__.lower()}-{hunt_name}"
        attr = Attribute(label='hunt-name', value=hunt_name)
        has.append(attr)

        if not add_as_enrichment:
            hunt = Relation(
                label='hunt',
                has = has,
                players = {},
            )
        else:
            hunt = Relation(
                label='enrichment',
                has = has,
                players = {},
            )

        if source_things:
            if not isinstance(source_things, list):
                source_things = [source_things]
            hunt.players['enriches'] = source_things

        _log.info(f"Adding Hunt: {hunt}")
        _log.debug(pformat(hunt.to_dict()))
        added_hunt = dbc.add_thing(hunt, return_things=return_things)
        return added_hunt

    def add_enrichments(
        self,
        dbc: ConnectorPlugin = None,
        things: List[object] = [],
        con_threshold: Optional[float] = None,
    ):
        """Add enrichments based on Thing labels
        Automatically adds enrichment pivots/hunts to graph based on what type
        of Thing they are. Basically, if an 'ip' entity exists in the DB and
        either it or its parent Hunt has a confidence > 0.0, then automatically
        generate an Enrichment Relation for that entity.

        :param dbc: Database connector
        :param things: List of Things to auto-pivot on
        :param con_threshold: Confidence threshold for which to determine an
            auto-pivot is warranted. Defaults to 1.0 or 'Low' confidence.

        :returns: dictionary of all_active_hunts. Example:
            {'endpoint': [hunt1,hunt2]}
        """
        _log = self.logger
        con_threshold = con_threshold or self.con_threshold
        all_active_hunts = {}
        added_hunts = {}

        if not dbc:
            _log.error(f"Database connector plugin required to add enrichments!")
            return all_active_hunts

        if not hasattr(self, 'enrich_map') or not self.enrich_map:
            self._gen_enrich_map(
                dbc = dbc
            )

        for thing in things:
            # Check for valid Thing types
            if thing.label not in self.enrich_map:
                _log.info(f"{thing.label} is not a supported entity type.")
                continue

            # Ignore entities with certain tags
            ignore_me = False
            for attr in thing.has:
                if attr.label == 'tag':
                    if attr.value in self.enrich_ignore_tags:
                        ignore_me = True
                        break
            if ignore_me:
                _log.debug(
                    f"Ignore tag found: {attr.value} - skipping {thing}!"
                )
                continue

            # Ignore entities with low confidence threshold
            ignore_me = self._con_threshold_check(
                dbc=dbc,
                thing=thing,
                con_threshold=con_threshold,
            )

            if ignore_me:
                _log.info(
                    f"Confidence threshold too low for {thing}!"
                )
                continue

            keyattr = self.enrich_map[thing.label]['key']
            # Loop through potential endpoints for this thing type
            for endpoint in self.enrich_map[thing.label]['endpoints']:
                # for comparisons, we need to get the proper endpoint name
                endpoint = f"{self.__class__.__name__.lower()}_{endpoint}"
                # if we made it this far, time to get the whole thing
                thing = dbc.find_things(thing, search_mode='full')[0]
                if not hasattr(thing, 'relations'):
                    _log.info(f"{thing} has no attribute 'relations'!")
                    continue

                # Check if enrichment already exists
                enrich_exists = False
                enrich_hunt_name = None
                for rel in thing.relations:
                    for attr in rel.has:
                        if attr.label=='hunt-endpoint':
                            if attr.value==endpoint:
                                enrich_exists= True
                                enrich_hunt_name = rel.get_attributes('hunt-name', first_only=True)
                                break
                    if enrich_exists:
                        break
                if enrich_exists:
                    _log.info(f"{endpoint} enrichment already exists for {thing}")
                    if enrich_hunt_name and enrich_hunt_name not in thing.has:
                        _log.warning(f"Somehow {enrich_hunt_name.value} is missing from {thing}!")
                        _log.warning(f"Adding {enrich_hunt_name.value} to {thing}!")
                        dbc.attach_attribute(thing, enrich_hunt_name)
                    continue

                # Use the value of this thing's keyattr for its enrichment query
                # string as well as its hunt name.
                if endpoint not in added_hunts:
                    added_hunts[endpoint] = {}
                keyval = None
                if thing.get_attributes(keyattr, first_only=True):
                    keyval = str(thing.get_attributes(keyattr, first_only=True).value)
                if keyval is None:
                    _log.error(f"No valid keyvalue found for {thing}!")
                    continue
                if keyval not in added_hunts[endpoint]:
                    added_hunts[endpoint][keyval] = []

                # Add this thing to the list of things that will be added to the
                # new enrichment Relation as its source_thing. The new enrichment
                # will point to these things as "enriches".
                added_hunts[endpoint][keyval].append(thing)

        for endpoint, keyvals in added_hunts.items():
            # api_conf = None
            # Get the appropriate APIConf object for this endpoint

            '''
            for ac in self.api_confs:
                if f"{self.__class__.__name__.lower()}_{ac.endpoint}" == endpoint:
                    api_conf = copy.deepcopy(ac)
                    break

            if api_conf is None:
                _log.error(f"No APIConfig found for endpoint {endpoint}!")
                continue
            '''

            ep = endpoint.replace(f"{self.__class__.__name__.lower()}_","")
            _log.info(f"self.api_confs: {self.api_confs}")
            ac = self.api_confs.get(ep)
            if ac is None:
                _log.error(f"No APIConfig found for endpoint {endpoint} or {ep}!")
                continue

            api_conf = copy.deepcopy(ac)


            for kv, things in keyvals.items():
                # Set the APIConf query string
                api_conf.params[self.param_query_key] = kv
                # Add the new enrichment
                hunt_name = api_conf.hunt_name.format(query=kv)
                if not hunt_name.startswith(f"{self.__class__.__name__.lower()}-"):
                    hunt_name = f"{self.__class__.__name__.lower()}-{hunt_name}"
                hn = Attribute(label='hunt-name', value=hunt_name)
                new_hunt = self.add_hunt(
                    dbc=dbc,
                    api_conf=api_conf,
                    hunt_active=api_conf.hunt_active,
                    hunt_name=hunt_name,
                    add_as_enrichment=True,
                    source_things=things,
                    return_things=True,
                )
                # Add the hunt_name to all associated things
                if new_hunt:
                    for th in things:
                        hunt_names = th.get_attributes('hunt-name')
                        if hn not in hunt_names:
                            dbc.attach_attribute(th, hn)
                if endpoint not in all_active_hunts:
                    all_active_hunts[endpoint] = []
                all_active_hunts[endpoint].append(new_hunt)

        _log.info(f"Added enrichments: {all_active_hunts}")
        return all_active_hunts

    def bulk_add_hunt_results(
        self,
        dbc: ConnectorPlugin = None,
        hunt_results: Dict = {},
        force: Optional[bool]=False,
    ):
        """Add hunt results in bulk
        Add hunt results in bulk

        :param dbc: Database ConnectorPlugin
        :param hunt_results: value returned from run_hunts()
            hunt_results = {
                'censys_host-details': {
                    'censys-192.168.1.100': {
                        'hunt': <hunt_object>,
                        'found': {
                            'things': [<thing_1>, <thing_2>],
                            'raw': <raw_json_response>,
                        },
                        'cached': False,
                    }
                }
            }
        :param force: If True, all things are added, regardless of whether or not
            they already exist.

        :returns: True
        """
        _log = self.logger

        bulk_add = {
            'attributes': [],
            'entities': [],
            'relations': [],
        }
        added_hunts = []

        _log.info(f"Adding {self.__class__.__name__} Hunt Results...")
        for _, hunt_names in hunt_results.items():
            for hunt_name, hunt_found in hunt_names.items():
                hunt = hunt_found['hunt']
                found = hunt_found['found']
                if not found['things']:
                    continue
                hunt_name_attr = Attribute(label='hunt-name', value=hunt_name)

                if 'found' not in hunt.players:
                    hunt.players['found'] = []
                for thing in found['things']:
                    if isinstance(thing, Attribute):
                        if thing not in hunt.has:
                            hunt.has.append(thing)
                            continue
                    if isinstance(thing, Relation):
                        for _, players in thing.players.items():
                            for player in players:
                                # add the hunt-name attribute to any entities
                                # this relation may have discovered
                                if hunt_name_attr not in player.has:
                                    player.has.append(hunt_name_attr)
                                # make sure anything a connected relation discovered
                                # is also related to the original hunt
                                if player not in hunt.players['found']:
                                    hunt.players['found'].append(player)
                        # finally, add the relation to the bulk-add
                        bulk_add['relations'].append(thing)

                    if thing not in hunt.players['found']:
                        if not isinstance(thing, Attribute):
                            # basically, we're only adding Entities and Relations
                            # as players to this hunt
                            # add the hunt-name attribute to the relation or entity
                            # that was discovered
                            if hunt_name_attr not in thing.has:
                                thing.has.append(hunt_name_attr)
                            # Add the entity or relation as a 'found' thing stemming
                            # from the original hunt.
                            hunt.players['found'].append(thing)
                            if isinstance(thing, Entity):
                                bulk_add['entities'].append(thing)

                # add date-seen to hunt
                bulk_add['relations'].append(hunt)
                added_hunts.append(hunt)
        _log.info(
            f"\n\t[{self.__class__.__name__}] - Running dbc.bulk_add for "
            f"\n\t{len(bulk_add['attributes'])} attributes, "
            f"\n\t{len(bulk_add['entities'])} entities, and "
            f"\n\t{len(bulk_add['relations'])} relations..."
        )
        dbc.bulk_add(bulk_add, force=force)
        _log.info(f"Finished updating {len(added_hunts)} {self.__class__.__name__} hunts!")

        return True

    def check_dateseen(
        self,
        thing: Thing = None,
        alt_time: Optional[Attribute] = None,
    ):
        """Ensure a particular Thing has at least one date-seen attached.
        :param thing: Thing to check whether or not it has a date-seen Attribute
        :param alt_time: Before attaching a date-seen Attribute matching
            now(timestamp.utc), check use this Attribute instead (if it exists)
        """
        if not thing.get_attributes('date-seen', first_only=True):
            if alt_time and alt_time.value is not None:
                thing.has.append(alt_time)
            else:
                now = Attribute(
                    label='date-seen',
                    value=datetime.now(timezone.utc)
                )
                thing.has.append(now)
        return thing

    def find_active_hunts(
        self,
        dbc: ConnectorPlugin = None,
        ignore_freq: bool = False,
        iid: Optional[str] = '',
    ):
        """
        Finds all active "huntable" objects for the service. The following
        requirements must be met in order for it to be passed on to the next
        step:

            - Have hunt-active == True
            - Have a hunt-endpoint
            - Have a hunt-string
            - Have a hunt-name
            - Have hunt-service == '{plugin}'
            - Have a last-seen OLDER/LESS THAN than (now()-(frequency*60*60))

        :params ignore_freq: Ignore the search frequency thresholds and include
            the hunt regardless of when it was last run.

        :returns: Dict of active hunts. Example:
            {'endpoint': [hunt1, hunt2]}

        """

        _log = self.logger
        all_active_hunts = {}

        found_hunts = self._find_active_hunts(dbc, ignore_freq, iid=iid)
        _log.debug(f"Found hunts: {found_hunts}")

        for hunt in found_hunts:
            for attr in hunt.has:
                if attr.label == 'hunt-endpoint':
                    endpoint = attr.value

            if endpoint not in all_active_hunts:
                all_active_hunts[endpoint] = [hunt]
            else:
                all_active_hunts[endpoint].append(hunt)

        return all_active_hunts

    def flat_dict(self, dict):
        return flatten_dict(dict)

    def get_trigger_date(
        self,
        thing: Relation = None,
    ):
        """Get trigger date for Hunt-or-Kill logic checks

        Compares date-discovered, last-seen, and hok:hunted:* notes to get the
        last time a decision was made regarding this thing, and uses that date
        for future hunt-or-kill logic.

        :param thing: The enrichment we're determining to hunt or kill

        :returns: datetime object of trigger date
        """
        _log = self.logger
        trigger_date = datetime(2000,1,1,0,0, tzinfo=timezone.utc)
        attr = thing.get_attributes('date-discovered', first_only=True)
        if attr and attr.value.replace(tzinfo=timezone.utc) > trigger_date:
            trigger_date = datetime(
                attr.value.year,
                attr.value.month,
                attr.value.day,
                23,
                59,
                59,
                tzinfo=timezone.utc
            )
        '''
        # Leaving out last-seen because it's inherently always going to be
        # pushed back any time it finds new results, effectively resetting any
        # timers that are reliant on the last time a human interacted with this
        # particular enrichment.
        attr = thing.get_attributes('last-seen', first_only=True)
        if attr and attr.value.replace(tzinfo=timezone.utc) > trigger_date:
            trigger_date = datetime(
                attr.value.year,
                attr.value.month,
                attr.value.day,
                23,
                59,
                59,
                tzinfo=timezone.utc
            )
        '''
        notes = thing.get_attributes('note')
        attr = None
        for note in notes:
            if note.value.startswith('hok:hunted:'):
                attr = note
                break
        dto = None
        if attr:
            date_string = attr.value.split(":")[-1]
            dto = datetime.strptime(date_string, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        if dto and dto > trigger_date:
            trigger_date = datetime(
                dto.year,
                dto.month,
                dto.day,
                23,
                59,
                59,
                tzinfo=timezone.utc
            )
        return trigger_date

    def hok_decision(
        self,
        dbc: ConnectorPlugin = None,
        thing: Relation = None,
        reason: Optional[str] = None,
        hunted: Optional[bool] = False,
    ):
        """Hunt-or-kill Hunt Action
        A user has decided `thing` is worth continuing to hunt for.

        Process:
            - Set `hunt-active` attribute to True
            - Remove `hok:*` tags to thing
            - Add `hok:<reason>` tag to thing
            - Remove `hok:*` notes from thing
            - Add `hok:hunted|killed:<date>` note to thing

        :param dbc: Database ConnectorPlugin for checking logic
        :params thing: 'Enrichment' or 'Hunt' relation object
        :params reason: Reason for the hok_trigger firing
        :params hunted: If True, re-enable hunt. If False, leave as-is
        :returns: True
        """
        _log = self.logger

        if hunted:
            hunt_active = Attribute(label='hunt-active', value=True)
            dbc.replace_attribute(thing, hunt_active)

        # Handle tags
        tags = thing.get_attributes('tag')
        for tag in tags:
            if tag.value.startswith('hok:'):
                dbc.detach_attribute(thing, tag)

        if not reason:
            reason = "no-reason-given"
        hok_tag = Attribute(label='tag', value=f'hok:{reason}')
        dbc.attach_attribute(thing, hok_tag)

        # Handle notes
        notes = thing.get_attributes('note')
        for note in notes:
            if note.value.startswith('hok:'):
                dbc.detach_attribute(thing, note)

        now = datetime.now(timezone.utc)
        now_str = now.strftime("%Y-%m-%d")
        if hunted:
            note = Attribute(label='note', value=f'hok:hunted:{now_str}')
        else:
            note = Attribute(label='note', value=f'hok:killed:{now_str}')
        dbc.attach_attribute(thing, note)

        return True

    def hok_trigger(
        self,
        dbc: ConnectorPlugin = None,
        thing: Relation = None,
        reason: Optional[str] = None,
    ):
        """Trigger Hunt-or-Kill
        Trigger Hunt-or-Kill condition. This is the generic function that's called
        when the necessary logic is met to temporarily disable an automated enrichment.

        Process:
            - Set thing `hunt-active` attribute to False
            - Add `hok:hunt-or-kill` tag to thing
            - Add `hok:<date>:<reason>` note to thing

        :param dbc: Database ConnectorPlugin for checking logic
        :params thing: 'Enrichment' or 'Hunt' relation object
        :params reason: Reason for the hok_trigger firing
        :returns: True
        """
        _log = self.logger
        hunt_active = Attribute(label='hunt-active', value=False)
        dbc.replace_attribute(thing, hunt_active)
        hok_tag = Attribute(label='tag', value='hok:hunt-or-kill')
        dbc.attach_attribute(thing, hok_tag)

        now = datetime.now(timezone.utc)
        # now_round = datetime(now.year, now.month, now.day)
        now_str = now.strftime("%Y-%m-%d")
        if not reason:
            reason = "No reason given"
        note = Attribute(label='note', value=f'hok:{now_str}:{reason}')
        dbc.attach_attribute(thing, note)

        return True

    def purge_empty_things(self, things: List[Thing] = []):
        """Gets rid of all None objects in a list of Things
        :param things: List of things to search for None objects in

        :returns: List of things with all the Nones removed
        """
        _log = self.logger
        for thing in things:
            if isinstance(thing, (Entity, Relation)):
                while None in thing.has:
                    thing.has.remove(None)
            if isinstance(thing, Relation):
                for role, players in thing.players.items():
                    while None in players:
                        players.remove(None)
                    for player in players:
                        while None in player.has:
                            player.has.remove(None)
        while None in things:
            things.remove(None)
        return things

    def rate_limit_respect(
        self,
        last_time: int = 0,
        rate_limit: int = 3,
        target_time: Optional[int] = 0,
    ):
        """
        Confirm the rate limit has been respected for a given plugin.
        If rate limit hasn't been met, sleep until it has.

        :param last_time: last time search was run in epoch
        :param rate_limit: amount of seconds to wait before next API request can
            be made

        """

        _log = self.logger
        now = time()
        if target_time:
            specified_wait = target_time - now
            _log.info(f"Rate limit not hit! Waiting {specified_wait} seconds...")
            sleep(specified_wait)
            return True

        now = time()
        target_time = last_time + rate_limit
        if now >= target_time:
            return True
        self.rate_limit_respect(
            last_time=last_time,
            rate_limit=rate_limit,
            target_time=target_time
        )

    def run_hok(
        self,
        dbc: ConnectorPlugin = None,
    ):
        """Run hunt or Kill Checks
        :param dbc: Database ConnectorPlugin
        """
        _log = self.logger

        # Get endpoints that require checking
        hok_eps = {}
        for endpoint, ac in self.api_confs.items():
            if ac.hok_logic:
                if ac.endpoint.startswith(f"{self.__class__.__name__.lower()}_"):
                    ep = ac.endpoint
                else:
                    ep = f"{self.__class__.__name__.lower()}_{ac.endpoint}"
                if ep not in hok_eps:
                    hok_eps[ep] = ac.hok_logic

        active_enrichments = []
        hunt_active = Attribute(label='hunt-active', value=True)
        for ep, _ in hok_eps.items():
            hunt_ep = Attribute(
                label='hunt-endpoint',
                value=ep,
            )
            ae_frame = Relation(label='enrichment', has=[hunt_active, hunt_ep])
            results = dbc.find_things(
                ae_frame,
                search_mode='no_backtrace',
                include_meta_attrs=True,
            )
            active_enrichments = list(set(active_enrichments + results))

        for ae in active_enrichments:
            hok = None
            endpoint = ae.get_attributes('hunt-endpoint', first_only=True).value
            if endpoint in hok_eps:
                hok = hok_eps[endpoint]
            if hok is None:
                continue
            # Run hunt or kill logic against hunt
            if hok(
                dbc=dbc,
                thing=ae
            ):
                _log.info(f"Hunt-or-Kill Logic tripped for {ae}!")
        return True

    def run_hunts(
        self,
        active_hunts: Dict = {},
        cached_hunts: Optional[Dict[str,str]] = "",
    ):
        """Run Active Hunts found in the database
        After being fed a list of active hunts (Relation Objects labeled "hunt"
        in the DB with "hunt-service" attribute == <this_service>), pull out their
        details (e.g. query string) and run them against the <service> API.

        NOTE: Before ever getting here we should have checked that all hunt
            objects meet the following requirements:
            - Have hunt-active == True
            - Have a hunt-endpoint
            - Have a hunt-string
            - Have a hunt-name
            - Have hunt-service == <this_service>
            - Have a last-seen OLDER/LESS THAN than (now()-(frequency*60*60))

        :param dbc: The database connector object that talks to the appropriate DB
        :param active_hunts: {'endpoint': [hunt1,hunt2]}
        :param cached_hunts: a Dict that points to cached data used for testing.
            e.g. {
                'endpoint': {
                    'hunt_name' : './ledhntr/plugins/censys/cached_data/hosts_search.json'
                }
            }

        :returns: Dict of hunt_results. Example:
            {
                'endpoint': {
                    'hunt_001': {
                        'hunt': Relation(label='hunt'),
                        'found': {
                            'things': [thing1, thing2],
                            'raw': {<raw_json>},
                        },
                        'cached': False
                    }
                }
            }
        """

        _log = self.logger
        hunt_results = {}

        for endpoint, hunts in active_hunts.items():
            # ep = endpoint.lstrip(f"{self.__class__.__name__.lower()}_")
            # ac = self.api_confs.get(ep)
            api_conf=None
            for ep, ac in self.api_confs.items():
                _log.info(f"self.api_confs: {self.api_confs}")
                # _log.info(f"Checking APICOnf: {self.__class__.__name__.lower()}_{ep}")
                if f"{self.__class__.__name__.lower()}_{ep}" == endpoint:
                    api_conf = copy.deepcopy(ac)
                    break
            if api_conf is None:
                _log.error(f"Unable to find APIConf for endpoint {endpoint}!")
                continue
            api_conf = copy.deepcopy(ac)

            for hunt in hunts:
                hunt_name = hunt.iid
                for attr in hunt.has:
                    if attr.label == 'hunt-string':
                        query = attr.value
                        api_conf.params[self.param_query_key] = query
                    if attr.label == 'hunt-name':
                        hunt_name = attr.value

                cached_data = False
                if cached_hunts:
                    if endpoint in cached_hunts:
                        if hunt_name in cached_hunts[endpoint]:
                            if cached_hunts[endpoint][hunt_name]:
                                cached_data = cached_hunts[endpoint][hunt_name]
                            else:
                                cached_data = False
                else:
                    cached_data = False

                search_res = self.search(
                    api_conf=api_conf,
                    cached_data = cached_data,
                    hunt = hunt,
                )

                if endpoint not in hunt_results:
                    hunt_results[endpoint] = {
                        hunt_name: {}
                    }

                if not search_res:
                    search_res = {'error': 'search failed and returned 0 results!'}

                if cached_data:
                    cached = True
                else:
                    cached = False
                    # If not cached, set date-seen for hunt as now
                    now = datetime.now(timezone.utc)
                    now_attr = Attribute(label='date-seen', value=now)
                    hunt.has.append(now_attr)

                hunt_results[endpoint][hunt_name] = {
                    'hunt': hunt,
                    'found': search_res,
                    'cached': cached,
                }

        return hunt_results

    def scrub_junk(
        self,
        flat_res: Dict = None,
        ignored_keys: Dict = None,
    ):
        """
        scrub data we literally want nothing to do with
        """

        '''
        ignored_keys = {
            "startswith": [],
            "endswith": [
                "perspective_id",
            ],
            "equals": [],
            "contains": [
                "__"
            ],
            "matches": [
                <re.compile>,
            ]
        }
        '''
        bad_keys = []
        clean_res = {}
        for longkey, value in flat_res.items():
            found_long_key = False
            for ik, iv in ignored_keys.items():
                if found_long_key:
                    break
                if ik == "startswith":
                    for longkeymatch in iv:
                        if longkey.startswith(longkeymatch):
                            bad_keys.append(longkey)
                            found_long_key = True
                            break
                elif ik=="endswith":
                    for longkeymatch in iv:
                        if longkey.endswith(longkeymatch):
                            bad_keys.append(longkey)
                            found_long_key = True
                            break
                elif ik=="equals":
                    for longkeymatch in iv:
                        if longkey == longkeymatch:
                            bad_keys.append(longkey)
                            found_long_key = True
                            break
                elif ik=="contains":
                    for longkeymatch in iv:
                        if longkeymatch in longkey:
                            bad_keys.append(longkey)
                            found_long_key = True
                            break
        for k, v in flat_res.items():
            if k not in bad_keys:
                clean_res[k] = v
        return clean_res

    def search(
        self,
        api_conf: Optional[APIConfig] = None,
        cached_data: Optional[str] = "",
        hunt: Optional[Relation] = None,
        simple: Optional[dict] = {},
    ):
        """Search API endpoints
        Given a fully-modified APIConfig object, run an API search with
        those parameters.

        :param api_conf: APIConfig object with proper options set
            (usually via run_hunts())
        :param cached_data: [Optional] Location of cached data to use instead of
            burning a live API call.
        :param hunt: An optional Hunt Relation object used for passing dates
            seen to the caching mechanism
        :param simple: A dict containing an endpoint and a query. Query key optional.
            {
                'endpoint': 'hosts',
                'query': '192.168.1.100',
                'key': 'query', # optional - defaults to self.param_query_key
            }
            api_conf will be configured with this data  before the search is run.
            key is optional, and if not provided self.param_query_key will be used.

        :returns: search_res Dictionary. Example:
            search_res = {
                'things': things,
                'raw': raw_json,
            }
        """
        _log = self.logger

        # some weird stuff is going on with api_conf caching. This should help
        # break those problems
        new_api_conf = copy.deepcopy(api_conf)
        api_conf = new_api_conf

        search_res = {
            'things': [],
            'raw': {},
        }

        pqk = None

        # Handle a simple search
        if simple:
            ep = simple.get('endpoint')
            q = simple.get('query')
            if not ep:
                _log.error(
                    f"simple searches require a valid endpoint. "
                    f"Was provided endpoint: {ep}"
                )
                return search_res

            # If we don't have a custom api_conf passed to the function, we'll
            # start with a fresh one for this endpoint
            if not api_conf:
                ac = self.api_confs.get(ep)
                if not ac:
                    _log.error(f"Unable to find APIConf for endpoint {endpoint}!")
                    return search_res
                api_conf = copy.deepcopy(ac)

        # Determine proper param_query_key
        ## If key was explicitly provided, that takes precedence.
        ## If api_config has param_query_key set, that takes second order.
        ## If api_config does not have param_query_key set, attempt to use
        ##   self.param_query_key
        ## If we still end up with None, then the endpoint might still be valid
        ##   in the case of something like get_all_reports or get_account_stats
        ##   where it's essentially query-less
        if api_conf.param_query_key is not None:
            pqk = simple.get('key') or api_conf.param_query_key or \
                self.param_query_key or None

        # If param_query_key is set, validate that a corresponding param is set.
        ## For APIs that accept either/or search options, param_query_key
        ## might be a tuple. In that case, we'll take the first key with a value
        ## to set as the param_query_key.
        if pqk:
            valid_params = False
            if isinstance(pqk, tuple):
                key_opts = copy.deepcopy(pqk)
                for ko in key_opts:
                    if api_conf.params.get(ko) is not None:
                        pqk = ko
                        valid_params=True
                        break
                if not valid_params:
                    _log.error(
                        f"{api_conf.endpoint} requires one of these keys to be "
                        f"set: {pqk}!"
                    )
                    return search_res

            api_conf.param_query_key = pqk
            # Regardless of whether or not an api_conf was provided, if we run
            # a simple search, those values must be respected.
            if simple and q:
                api_conf.params[pqk] = q

            if api_conf.params.get(pqk):
                valid_params=True
            if not valid_params:
                _log.error(
                    f"{api_conf.endpoint} requires one of these keys to be "
                    f"set: {pqk}!"
                )
                return search_res

        if not api_conf:
            _log.error(f"api_conf required to run search!")
            return search_res
        if not api_conf.endpoint:
            _log.error(f"Endpoint required to run search!")
            return search_res

        _log.info(
            f"Running {self.__class__.__name__} search against "
            f"endpoint {api_conf.endpoint}"
        )

        # Set request params
        if "{query}" in api_conf.uri:
            if not pqk or not api_conf.params[pqk]:
                _log.error(
                    f"Query key and query value required for {api_conf.endpoint}!"
                )
                return search_res
            api_conf.uri = api_conf.uri.format(query=api_conf.params[pqk])
        reqkwargs = self._set_request_args(api_conf)

        # Check Caching and if enabled, modify endpoint to reflect that
        data = []
        endpoint = copy.deepcopy(api_conf.endpoint)

        if cached_data:
            _log.info(f"cached data supplied! {cached_data}")
            try:
                if os.path.exists(cached_data):
                    with open(cached_data, 'r') as f:
                        data = f.read()
                    data = json.loads(data)
                    # api_conf.endpoint = f"cached_{api_conf.endpoint}"
                    endpoint = f"cached_{endpoint}"
                else:
                    _log.warning(
                        f"Fed cached_data {cached_data} but file does not exist!"
                        " running live query instead!"
                    )
            except Exception as e:
                _log.error(f"Error loading cached data {cached_data}.")
                _log.error(f"{e}")
                data = {'_error': cached_data}
                pass

        if not endpoint.startswith('cached_'):
            try:
                # LIVE FIRING THE API!!!
                data = self._fire_api(api_conf, reqkwargs)
                if not isinstance(data, (dict, list)):
                    _log.error(
                        f"Error running query against {endpoint} "
                        f"status: {data.status_code} - {data.text}"
                    )
                    _log.error(
                        f"reqkwargs:\n{pformat(reqkwargs)}"
                    )
                    _log.error(
                        f"res:\n{pformat(data)}"
                    )
                    search_res['raw'] = data
                    return search_res

            except Exception:
                _log.error(
                    f"Erroring querying endpoint {endpoint}!",
                    exc_info=True
                )
                return search_res

        # increase API counters
        self._inc_api_counter(endpoint)

        if cached_data:
            dates_seen = hunt.get_attributes(label='date-seen')
            check_dates = []
            for ds in dates_seen:
                if ds.value not in check_dates:
                    check_dates.append(ds.value)

            # Calling parser with check_dates option set determines if this data
            # has already been parsed and added to the DB.
            if api_conf.parser is None:
                _log.debug(f"Endpoint {api_conf.endpoint} does not have a parser set.")
                already_parsed = False
            else:
                already_parsed = api_conf.parser(
                    raw = data,
                    api_conf = api_conf,
                    check_dates = check_dates,
                )
            if already_parsed:
                _log.info(
                    f"{hunt} appears to already have been parsed and added on "
                    f"{already_parsed}"
                )
                search_res['raw'] = data # data is really just empty in this case
                return search_res
            else:
                _log.debug(
                    f"{hunt} was not parsed yet. last_seen was not in {pformat(check_dates)}"
                )

        # Parse the results into appropriate Thing objects
        if api_conf.parser is None:
            _log.debug(f"No parser set for {api_conf.endpoint}. things=[]")
            things = []
        else:
            try:
                things = api_conf.parser(
                    raw = data,
                    api_conf = api_conf,
                )
            except Exception as e:
                _log.error(f"Error parsing things: {e}")
                things = []

        # Clean any potential None objects that got sucked up in the mix
        try:
            things = self.purge_empty_things(things)
        except Exception as e:
            _log.error(f"Error purging empty things: {e}")
            things = []

        # Add confidence = 0 to all Entities and Relations that don't have
        # their confidence already set
        try:
            things = self._set_confidence(things)
        except Exception as e:
            _log.error(f"Error setting confidence for all things: {e}")
            things = []

        search_res = {
            'things': things,
            'raw': data,
        }

        return search_res
