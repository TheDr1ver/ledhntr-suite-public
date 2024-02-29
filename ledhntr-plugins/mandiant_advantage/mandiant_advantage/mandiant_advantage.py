"""
Overview
========

Use this plugin to interact with the Mandiant Advantage API

NOTE - This needs major reworkings to make it APIConf-compatible like the rest
of the HNTRPlugins, but it was the whole reason I managed to get those things
uniform in the first place, so I'm happy about that at least :)

Basically every parser needs to take check_dates and raw into account, and they
all need to return lists of parsed Thing Objects instead of random dicts etc.

"""

import base64
import copy
import json
import logging
import os
import re

import requests
from pkg_resources import resource_stream
from pprint import pformat
from datetime import datetime, timezone, timedelta
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

class MandAd(HNTRPlugin):
    """Mandiant Advantage HNTR Plugin
    Mandiant Advantage API interaction

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
            fallback = 'https://api.intelligence.mandiant.com/',
        )
        if not self.base_url.endswith("/"):
            self.base_url+="/"

        self.reports_base_url = config.get(
            'options',
            'reports_base_url',
            fallback = "https://advantage.mandiant.com/reports/"
        )
        if not self.reports_base_url.endswith("/"):
            self.reports_base_url+="/"

        self.api_version = config.get(
            'options',
            'api_version',
            fallback = 'v4',
        )

        self.days_back = int(config.get(
            'options',
            'days_back',
            fallback = '7',
        ))

        self.search_limit = int(config.get(
            'options',
            'search_limit',
            fallback = '100',
        ))

        self.app_name = config.get(
            'options',
            'app_name',
            fallback = "LEDHNTR Example MandAd App Name"
        )

        self.pub_key = config.get(
            'options',
            'pub_key',
            fallback = '',
        )

        self.priv_key = config.get(
            'options',
            'priv_key',
            fallback = '',
        )

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
            fallback = '4',
        ))

        self.rate_limit = int(config.get(
            'options',
            'rate_limit',
            fallback = '1',
        ))

        self.http_proxy = config.get(
            'options',
            'http_proxy',
            fallback = '',
        )

        self.https_proxy = config.get(
            'options',
            'https_proxy',
            fallback = '',
        )

        self.bearer_time = 0
        self.bearer_token = None
        self._load_api_configs()

    def _load_bearer_token(
        self,
        force: Optional[bool] = False
    ):
        """Load Bearer Token
        :param force: Force the refresh of a bearer token - to be used
            when a function returns a 401 status_code.

        :returns: bearer_token or None
        """
        _log = self.logger

        # Check bearer token time limit (12 hrs)
        twelve_hrs_ago = int(time()) - (60*60*12)
        if self.bearer_time > twelve_hrs_ago and self.bearer_token and not force:
            return self.bearer_token

        auth_token_bytes = f"{self.pub_key}:{self.priv_key}".encode("ascii")
        base64_auth_token_bytes = base64.b64encode(auth_token_bytes)
        base64_auth_token = base64_auth_token_bytes.decode("ascii")

        headers = {
            'Authorization': f"Basic {base64_auth_token}",
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
            'X-App-Name': self.app_name,
        }

        params = {
            "grant_type": "client_credentials",
            "scope": "",
        }

        url = f"{self.base_url}token"

        self.rate_limit_respect(self.search_time, self.rate_limit)
        self.search_time = time()
        if self.http_proxy or self.https_proxy:
            proxies = {
                'http': self.http_proxy,
                'https': self.https_proxy,
            }
            resp = requests.post(url=url, headers=headers, data=params, proxies=proxies, verify=self.ssl_verify)
        else:
            resp = requests.post(url=url, headers=headers, data=params, verify=self.ssl_verify)

        if not resp.status_code==200:
            _log.error(f"Error obtaining bearer token: {resp.text}")
            self.bearer_token = None
        else:
            self.bearer_time = int(time())
            self.bearer_token = resp.json().get("access_token")
        return self.bearer_token

    def _calc_days_back_epoch(
        self,
        days_back: Optional[int] = None,
    ):
        """Used for calculating days_back epoch on the fly
        """
        _log = self.logger
        days_back = days_back or self.days_back
        return int(time()) - (60*60*24*days_back)

    def _load_api_configs(
        self,
    ):
        """Load API configs for this plugin
        """
        _log = self.logger
        self.api_confs = {}

        # Which param carries the default query
        self.param_query_key = "search"

        headers = {
            'Authorization': f"Bearer {self._load_bearer_token()}",
            'Accept': 'application/json',
            'X-App-Name': self.app_name,
        }

        now_epoch = int(time())

        # search
        c = APIConfig(
            endpoint = "search",
            uri = "v4/search",
            headers = headers,
            params = {
                "limit": self.search_limit,
                "next": None,
                "search": None,
                "sort_by": ["relevance"],
                "sort_order": "desc",
                "type": "all",
            },
            http_method=requests.post,
            parser = self.parse_search,
            add_to_db = None,
            simple_query_types = ["domain", "ip"],
            param_query_key=self.param_query_key,
            frequency = self.freq_threshold,
            hunt_active = False,
            hunt_name = "search_{query}",
            hok_logic = None,
        )
        self.api_confs[c.endpoint] = c

        # list reports
        c = APIConfig(
            endpoint = "reports",
            uri = "v4/reports",
            headers = headers,
            params = {
                "limit": self.search_limit,
                "offset": 0,
                "start_epoch": self._calc_days_back_epoch,
                "end_epoch": now_epoch,
                "next": None,
            },
            http_method=requests.get,
            parser = self.parse_list_reports,
            add_to_db = None,
            simple_query_types = [],
            param_query_key="start_epoch",
            frequency = self.freq_threshold,
            hunt_active = False,
            hunt_name = "list_reports_{query}",
            hok_logic = None,
        )
        self.api_confs[c.endpoint] = c

        # Get report
        c = APIConfig(
            endpoint = "report",
            uri = "v4/report/{query}",
            headers = headers,
            params = {},
            http_method=requests.get,
            parser = self.parse_report,
            add_to_db = None,
            simple_query_types = [],
            param_query_key = self.param_query_key,
            frequency = self.freq_threshold,
            hunt_active = False,
            hunt_name = "report_{query}",
            hok_logic = None,
        )
        self.api_confs[c.endpoint] = c

    def _get_all_results(
        self,
        api_conf: APIConfig = None,
        reqkwargs: dict = {},
        next: str = "",
        object_field: Optional[str] = "objects",
    ):
        """Get all results when the search_limit is reached
        :param api_conf: APIConfig of the endpoint being reached
        :param reqkwargs: Request arguments for the request. The 'params' args
            will be replaced with nothing but the 'next' field.
        :param next: When additional results are returned, the next parameter
            is populated and is valid for 10 minutes.
        :param object_field: Depending on the endpoint being reached, this field
            can have different values. When this field is empty, we know
            pagination is complete. (e.g. /reports & /search have 'objects' but
            /indicators has 'indicators')
        """
        _log = self.logger
        all_reports = []

        reqkwargs['params'] = {'next': next}

        self.rate_limit_respect(self.search_time, self.rate_limit)
        self.search_time = time()
        res = api_conf.http_method(**reqkwargs)

        if not str(res.status_code).startswith('2'):
            _log.error(
                f"Error obtaining reports: [{res.status_code}] - {res.text}"
            )
            return all_reports

        data = res.json()
        _log.debug(f"Response Keys: {list(data.keys())}")
        reports = data.get(object_field)
        all_reports += reports
        next = data.get('next')
        if next and reports:
            all_reports += self._get_all_results(api_conf, reqkwargs, next)

        return all_reports

    #################################################
    ### Non-Standard Functions
    #################################################

    # Handle Reports
    def _dict_to_attributes(
        self,
        data: dict = {},
        key: str = "",
        label: Optional[str] = "",
    ):
        """Convert dict key/val pair to a list of Attribute objects
        Given a dictionary, convert provided key/val pairs to Attribute objects.
            Example:
                data = {"test": ["val1", "val2"]}
                key = "test"
                label = "tag"

                Returns: [
                    Attribute(label="tag", value="val1"),
                    Attribute(label="tag", value="val2"),
                ]

                NOTE: label is optional, and overrides the key value as the
                resulting Attribute label.

        :param data: dict containing the data for conversion
        :param key: key to select from provided dictionary. Default value for
            resulting Attributes label
        :param label: Optionally override Attributes label with this value.

        :returns: List of Attributes
        """
        _log = self.logger
        attrs = []
        label = label or key

        values = data.get(key)
        if not values:
            # _log.error(f"No data found for key {key} in {data}")
            return attrs
        if not isinstance(values, list):
            values = [values]
        for val in values:
            if not isinstance(val, (str,int)):
                _log.error(
                    f"Expected str or int, not {type(val)}. Skipping!"
                )
                continue
            attr = Attribute(label=label, value=val)
            if attr not in attrs:
                attrs.append(attr)
        return attrs

    def _dict_to_entities(
        self,
        data: dict = {},
        key: str = "",
        label: Optional[str] = "",
        attr_label_map: Optional[dict] = {},
        ignore_keys: Optional[list] = [],
        only_keys: Optional[list] = [],
    ):
        """Convert dict key/val pair to a list of Entity objects
        Given a dictionary, convert provided data to a list of Entity objects.
            Example:
                data =
                    'files': [
                        {'md5': '1658fd7f1822f66e14cba4b8acf8df32',
                            'identifier': 'Related',
                            'name': 'payload.mem'},
                        {'md5': '014cb6da244f779747c07d7c3b9cba3f',
                            'identifier': 'Related',
                            'name': 'UNAVAILABLE'}
                    ]
                key = "files"
                label = "file"
                attr_label_map = {"name": "filename"}
                ignore_keys = ["identifier"]

                Returns:
                [
                    Entity(
                        label="file",
                        has=[
                            Attribute(
                                label="md5",
                                value="1658fd7f1822f66e14cba4b8acf8df32"
                            ),
                            Attribute(
                                label="filename", value="payload.mem"
                            )
                        ]
                    ),
                    Entity(
                        label="file",
                        has=[
                            Attribute(
                                label="md5",
                                value="014cb6da244f779747c07d7c3b9cba3f"
                            ),
                            Attribute(
                                label="filename", value="UNAVAILABLE"
                            )
                        ]
                    ),
                ]

        :param data: dict containing the data for conversion
        :param key: key to select from provided dictionary. Default value for
            resulting Entities labels
        :param label: Optionally override Entities label with this value.
        :param attr_label_map: Dictionary used for mapping alternative labels
            for dictionary keys in data
        :param ignore_keys: Ignore these keys when creating attributes
        :param only_keys: If set, only these keys will be converted to attributes

        :returns: List of Entities
        """
        _log = self.logger
        ents = []
        label = label or key

        attr_dicts = data.get(key)
        if not attr_dicts:
            # _log.error(f"No data found for key {key} in {data}")
            return ents
        if not isinstance(attr_dicts, list):
            attr_dicts = [attr_dicts]
        for ad in attr_dicts:
            has = []
            if not isinstance(ad, dict):
                _log.error(f"Expected to get a dictionary, instead got {ad}!")
                continue
            for k, val in ad.items():
                if k in ignore_keys:
                    # _log.debug(f"skipping ignored key {k}")
                    continue
                if only_keys and k not in only_keys:
                    # _log.debug(f"{k} is not one of {only_keys}!")
                    continue
                attr_label = attr_label_map.get(k) or k
                attrs = self._dict_to_attributes(
                    data=ad,
                    key=k,
                    label=attr_label,
                )
                for attr in attrs:
                    if attr not in has:
                        has.append(attr)
            if has:
                ent = Entity(label=label, has=has)
                if ent not in ents:
                    ents.append(ent)

        return ents

    def filter_reports(
        self,
        reports: list = [],
        filters: dict = {},
    ):
        """Filter returned reports
        Filter a list of returned reports to get rid of things we don't need
        and focus on things we do.

        :param reports: List of Report JSON summaries provided by get_reports()
        :param filters: Dictionary of filter requirements required for a report
            to match. Positive filters are run before negative filters. Example:
            {
                'positive': {
                    'intelligence_type': ['threat'],
                    'audience': ['fusion'],
                    'report_type': ["Event Coverage/Implication"],
                },
                'negative': {
                    'report_type': ["Threat Activity Alert"],
                },
            }

        :returns: List of filtered reports
        """
        _log = self.logger
        posf_reports = []
        filtered_reports = []

        filter_pos = filters.get('positive') or {}
        filter_neg = filters.get('negative') or {}

        # Handle positive filters
        if not filter_pos:
            posf_reports = reports
        else:
            for report in reports:
                report_added=False
                for k, vals in filter_pos.items():
                    for val in vals:
                        data = report.get(k) or []
                        if data and not isinstance(data, list):
                            data = [data]
                        if val in data and report not in posf_reports:
                            posf_reports.append(report)
                            report_added=True
                            # _log.info(f"{report['title']} added per {val}!")
                            break
                    if report_added:
                        break

        _log.info(f"positive filter results: {len(posf_reports)}")

        # Handle negative filters
        if not filter_neg:
            filtered_reports = posf_reports
        else:
            for report in posf_reports:
                report_removed = False
                for k, vals in filter_neg.items():
                    for val in vals:
                        data = report.get(k)
                        if data and not isinstance(data, list):
                            data = [data]
                        if val in data:
                            report_removed = True
                            # _log.info(f"{report['title']} removed per {val}!")
                            break
                    if report_removed:
                        break
                if not report_removed and report not in filtered_reports:
                    filtered_reports.append(report)

        _log.info(f"Final filter results: {len(filtered_reports)}")

        return filtered_reports

    def get_full_reports(
        self,
        reports: Optional[list] = [],
        report_ids: Optional[list] = [],
    ):
        """Get a list of full reports
        Given a list of report summaries or report IDs, return a list of the
        full associated reports.

        :param reports: List of report summaries as returned by get_reports()
        :param report_ids: List of report IDs, potentially sourced from manual
            entry.

        :returns: List of full reports in parsed dictionary format
        """
        _log = self.logger
        full_reports = []
        if not reports and not report_ids:
            _log.error(
                f"Either a list of report summaries (reports) or report IDs"
                f" is required to return a list of full reports."
            )
            return full_reports

        if reports:
            for report in reports:
                full_report = self.get_report(report['report_id'])
                if full_report and full_report not in full_reports:
                    full_reports.append(full_report)
        if report_ids:
            for report_id in report_ids:
                full_report = self.get_report(report_id)
                if full_report and full_report not in full_reports:
                    full_reports.append(full_report)

        return full_reports

    def get_report(
        self,
        report_id: str = "",
    ):
        """Get specific report by ID
        Given a report ID, return JSON details of the report.

        :param report_id: Mandiant report id to be downloaded
        :returns: dictionary of parsed report fields, or False if failure
        """
        _log = self.logger
        report = False

        self.rate_limit_respect(self.search_time, self.rate_limit)
        self.search_time = time()
        api_conf = self.api_confs.get('report')
        if api_conf is None:
            _log.error(f"No APIConfig set for the 'report' endpoint!")
            return report

        # Get report
        # Set default request arguments
        reqkwargs = self._set_request_args(api_conf)
        # Set specific report_id
        reqkwargs['url']=reqkwargs['url'].format(query=report_id)
        # Fire the API
        data = self._fire_api(api_conf, reqkwargs)
        if not isinstance(data, dict):
            if hasattr(data, 'status_code') and data.status_code:
                if data.status_code == 401:
                    api_conf['headers']['Authorization'] = f"Bearer {self._load_bearer_token()}"
                    data = self.fire_api(
                        api_conf=api_conf,
                        reqkwargs=reqkwargs,
                    )
                    if not isinstance(data, dict):
                        _log.error(f"Auth Failed! {data}")
                        return report
                else:
                    _log.error(f"[{data.status_code}] - {data.text}")
                    _log.error(f"Request Arguments: \n\t{pformat(reqkwargs)}")
                    raise
        return data

    def get_reports(
        self,

        days_back: Optional[int] = 0,
    ):
        """Get Mandiant Advantage Reports
        Get all reports from the last `days_back` days.

        :param days_back: Gather reports from this many days in the past. If not
            provided, defaults to the self.days_back value obtained from .conf.

        :returns: List of filtered reports
        """
        _log = self.logger
        all_reports = []

        api_conf = self.api_confs.get('reports')
        if api_conf is None:
            _log.error(f"No APIConfig set for the 'reports' endpoint!")
            return all_reports

        # Get all reports
        # Set default request arguments
        reqkwargs = self._set_request_args(api_conf)

        # Update days-back based on function param
        if days_back:
            _log.info(f"Using manually-provided days-back: {days_back}")
            days_back_epoch = int(time()) - (60*60*24*days_back)
            reqkwargs['params']['start_epoch'] = days_back_epoch

        # Fire the API
        data = self._fire_api(api_conf, reqkwargs)
        if not isinstance(data, dict):
            if hasattr(data, 'status_code') and data.status_code:
                if data.status_code == 401:
                    api_conf['headers']['Authorization'] = f"Bearer {self._load_bearer_token()}"
                    data = self.fire_api(
                        api_conf=api_conf,
                        reqkwargs=reqkwargs,
                    )
                    if not isinstance(data, dict):
                        _log.error(f"Auth Failed! {data}")
                        return all_reports

        # Paginate & parse the results
        _log.debug(f"Response Keys: {list(data.keys())}")
        reports = data.get("objects")
        all_reports = reports
        next = data.get('next')
        total_count = data.get('total_count')
        _log.info(f"Total results: {total_count}")
        # Exhaust pagination
        if next and reports:
            all_reports += self._get_all_results(api_conf, reqkwargs, next)
        _log.info(
            f"Search indicated {total_count} reports. Ultimately returned "
            f"{len(all_reports)} reports."
        )
        return all_reports

    def title_filters(
        self,
        reports: list = [],
        filters: dict = [],
    ):
        """Filter titles
        Filters titles based on regular expression matches. If a title matches,
        it gets dropped.

        :param reports: List of Report JSON summaries provided by get_reports()
        :param filters: List of regular expressions which, if they match, will
            drop the report from the list.

        :returns: List of final reports after filtering out bad titles.
        """
        _log = self.logger
        final_reports = []
        for report in reports:
            drop_it = False
            for filter in filters:
                if re.search(filter, report['title']):
                    drop_it=True
                    # _log.info(f"Filtering out {report['title']}")
                    break
            if not drop_it:
                final_reports.append(report)
        return final_reports

    #################################################
    #### PARSERS
    #################################################

    def parse_full_reports(
        self,
        full_reports: list = [],
        raw: Optional[dict] = {},
    ):
        """Parse list of full reports
        Given a list of full reports pulled down from Mandiant, parse the data
            and return it in LEDHNTR object format.
        :param full_reports: List of full_reports as returned by get_full_reports()
        :param raw: Raw response from Mandiant endpoint.

        :returns: Dict of LEDHNTR objects Example:
            {
                '22-00026655' : [
                    Attribute(label='title', value="Test Report"),
                    Entity(label='file', has=[Attribute(label='md5', value='1658fd7f1822f66e14cba4b8acf8df32')]),
                ]
            }
        """
        parsed_results = {}
        for fr in full_reports:
            objs = []
            # Get dict index
            report_id = fr.get('report_id')
            if not report_id:
                continue
            if report_id in parsed_results:
                continue

            # Add link to full report
            # https://advantage.mandiant.com/reports/22-00027046
            link = f"{self.reports_base_url}{report_id}"
            attr = Attribute(label='link', value=link)
            objs += [attr]

            # Parse Entities and Attributes

            # Summary
            attrs = self._dict_to_attributes(fr, 'executive_summary', 'summary')
            objs += attrs

            # Files
            ents = self._dict_to_entities(
                data=fr,
                key='files',
                label='file',
                attr_label_map = {
                    'name': 'filename',
                    'size': 'size-in-bytes',
                    'type': 'mime-type',
                },
                ignore_keys = ['identifier', 'actor'],
            )
            objs += ents

            # Networks
            networks = fr.get('networks') or []
            for net in networks:
                attrs = self._dict_to_attributes(net, 'domain-name')
                objs += attrs
                attrs = self._dict_to_attributes(net, 'ip', 'ip-address')
                objs += attrs

            # Metadata (Title, dates, links, etc.)
            attrs = self._dict_to_attributes(fr, 'title')
            objs += attrs
            attrs = self._dict_to_attributes(fr, 'date-published')
            objs += attrs

            # Report
            attrs = self._dict_to_attributes(fr, "threat_detail", "http-html")
            objs += attrs

            # Tags
            tags_data = fr.get('tags') or {}
            ## Actors
            actors = tags_data.get('actors') or []
            for actor in actors:
                name = actor.get('name')
                if not name:
                    continue
                objs += [Attribute(label='tag', value=name)]
                objs += [Attribute(label='actor-name', value=name)]
                aliases = actor.get('aliases')
                if not aliases:
                    continue
                for alias in aliases:
                    objs += [Attribute(label='alias', value=alias)]
            ## Malware
            malware = tags_data.get('malware_families') or []
            for m in malware:
                aliases = m.get('aliases') or []
                for a in aliases:
                    objs += [Attribute(label='tag', value=a)]
            ## Source country
            source = tags_data.get('source_geographies') or []
            for s in source:
                objs += [Attribute(label='tag', value=s)]

            parsed_results[report_id] = objs

        return parsed_results

    #################################################
    #### HUNT-OR-KILL LOGIC
    #################################################

    #### TODO
    def parse_search(
        self,
        raw: dict = {},
        api_conf: APIConfig = None,
    ):
        _log = self.logger
        _log.debug(f"Parsing search results...")

    def parse_list_reports(
        self,
        raw: dict = {},
        api_conf: APIConfig = None,
    ):
        _log = self.logger
        _log.debug(f"Parsing list of reports...")

    def parse_report(
        self,
        raw: dict = {},
        api_conf: APIConfig = None,
    ):
        _log = self.logger
        _log.debug(f"Parsing list of reports...")

    '''
    def hok_search(
        self,
    ):
        _log = self.logger
        _log.debug(f"Running hunt-or-kill logic for search endpoint...")
    '''
    # NOTE: search results are not DB-worthy... at least not at this time.