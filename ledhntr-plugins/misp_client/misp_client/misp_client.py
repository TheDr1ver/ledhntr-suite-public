"""
Overview
========

This is a connector plugin for interacting with a MISP instance.

"""

import copy
import json
import logging
import os
import re
import uuid

from datetime import datetime, timezone, timedelta
from pathlib import Path
from pprint import pformat

from bs4 import BeautifulSoup
from markdownify import markdownify, MarkdownConverter

from typing import (
    DefaultDict,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

from ledhntr.data_classes import (
    Attribute,
    Entity,
    Relation,
    Thing,
    Query
)
from ledhntr.helpers import LEDConfigParser
from ledhntr.helpers import format_date, dumps
from ledhntr.plugins.connector import ConnectorPlugin

from pymisp import (
    PyMISP,
    MISPObject,
    MISPEvent,
    MISPAttribute,
    MISPTag,
)

class CustomConverter(MarkdownConverter):
     """
     Convert one-row tables to pre blocks and strip alts from img
     """
     def convert_table(self, el, text, convert_as_inline):
         rows = el.find_all(['tr'])
         # print(f"len rows: {len(rows)}")
         if len(rows) <= 1:
             res = "\n\n```\n" + text + "\n```\n"
             print(res)
         else:
             res = "\n\n" + text + "\n"
         return res

     def convert_tr(self, el, text, convert_as_inline):
         cells = el.find_all(['td', 'th'])
         is_headrow = all([cell.name == 'th' for cell in cells])
         overline = ''
         underline = ''
         if is_headrow and not el.previous_sibling:
             underline += "| " + " | ".join(["---"] * len(cells)) + " |\n"
         elif not el.previous_sibling and not el.parent.name == "table":
             overline += "| " + " | ".join([''] * len(cells)) + " |\n"
             overline += "| " + " | ".join(['---'] * len(cells)) + " |\n"
         return overline + "|" + text + "\n" + underline

     def convert_img(self, el, text, convert_as_inline):
         alt = el.attrs.get('alt', None) or ''
         src = el.attrs.get('src', None) or ''
         title = el.attrs.get('title', None) or ''
         title_part = ' "%s"' % title.replace('"', r'\"') if title else ''
         if convert_as_inline:
             return alt

         return '![](%s%s)' % (src, title_part)

class MISPClient(ConnectorPlugin):
    """MISPClient
    """
    def __init__(
        self,
        config:LEDConfigParser,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        super().__init__(config)

        if not logger:
            self.logger: logging.Logger = logging.getLogger('ledhntr')
        _log = self.logger
        self.config = config

        self.url = config.get(
            'options',
            'url',
            fallback = 'https://localhost/',
        )
        if not self.url.endswith('/'):
            self.url += '/'

        key = config.get(
            'options',
            'key',
            fallback = '<your_api_key>',
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

        # Use this variable to enable fail-safes down-range, like preventing
        # an event from ever being published.
        self.test_run = config.get(
            'options',
            'test_run',
            fallback = 'false',
        )
        if self.test_run.lower() == "false":
            self.test_run = False
        elif self.test_run.lower() == "true":
            self.test_run = True

        self._load_misp(key=key)

    def _load_misp(
        self,
        key: str = "",
        url: Optional[str] = "",
        ssl_verify: Optional[str] = "",
    ) -> None:
        """Loads MISP instance for this object. Sets result to self.misp
        """
        _log = self.logger
        try:
            self.misp = PyMISP(self.url, key, ssl_verify)
        except Exception as e:
            _log.error(
                f"Exception occurred while loading MISP: {e}",
                exc_info=True
            )

    ############################################################################
    #### Generic Functions
    ############################################################################

    def get_past_date(
        self,
        days_back: int = 0,
    ):
        """Return datetime object from <days_back> days in the past
        """
        d = datetime.now() - timedelta(days=days_back)
        return d

    def misp_attr_map(self):
        """Returns mapping dictionary for LEDHNTR Thing objects -> MISP types
        """
        mam = {
            "actor-name": "threat-actor",
            "alias": "threat-actor",
            "domain-name": "domain",
            # "http-html": "comment", # TODO - Remove this, handle HTML as Markdown Report
            "ip-address": "ip-dst",
            "date-published": "datetime",
            "summary": "comment",
        }

        return mam

    def misp_event_meta_map(self):
        """Maps specific attribute labels to MISP Event metadata

        :returns: dictionary mapping attribute labels to kwargs keys to pass
            MISPEvent() when creating a new event.
        """
        meta_map = {
            "title": "info",
            "date-published": "date",
        }

        return meta_map

    def to_ids_map(self):
        """Maps to_ids yes/no to MISP Attribute Types
        Defines explicit MISPAttribute types that should or should not have
        the to_ids field set to True. Otherwise, it uses MISP's defaults.
        """
        to_ids_map = {
            'yes': [], # Use carefully
            'no': ['ip-dst'],
        }
        return to_ids_map

    def correlation_map(self):
        """Maps correlation yes/no to MISP Attribute Types
        Defines explicit MISPAttribute types that should or should not be
        correlated within the database. Otherwise it uses MISP's defaults.
        """
        correlation_map = {
            'yes': [],
            'no': ['tld'],
        }
        return correlation_map

    ############################################################################
    #### PyMISP Functions with Error Handling
    ############################################################################

    def add_event(
        self,
        event: MISPEvent = None,
    ):
        _log = self.logger
        _log.debug(f"Adding event {event}")
        try:
            event = self.misp.add_event(event, pythonify=True)
        except Exception as ex:
            _log.error(
                f"Error adding event {event}",
                exc_info=True
            )
            return False

        return event

    def add_object(
        self,
        obj: MISPObject = None,
        event: MISPEvent = None,
    ):
        _log = self.logger
        _log.debug(f"Adding object {obj} to event {event.info}")
        try:
            obj = self.misp.add_object(event, obj, pythonify=True)
        except Exception as ex:
            _log.error(
                f"Error adding object {obj} to event {event.info}",
                exc_info=True
            )
            return False

        return obj

    def delete_object(
        self,
        obj: MISPObject = None,
        hard: bool = True,
    ):
        _log = self.logger
        _log.debug(f"Deleting object {obj}")
        try:
            res = self.misp.delete_object(obj, hard=hard)
        except Exception as ex:
            _log.error(
                f"Error deleting object {obj}",
                exc_info=True
            )
            return False
        return res

    def get_attribute(
        self,
        attr_id: Union[str,int] = None,
    ):
        """Get Attribute by attribute ID
        :param attr_id: Attribute ID (int) or Attribute UUID (str)

        :returns: MISPAttribute or False if failed
        """
        _log = self.logger
        _log.debug(f"Getting attribute {attr_id}...")
        try:
            attr = self.misp.get_attribute(attr_id, pythonify=True)
        except Exception as ex:
            _log.error(f"Error getting attribute {attr_id}", exc_info=True)
            _log.error(f"Skipping attribute process.")
            return False

        if isinstance(attr, dict):
            _log.error(f"MISP returned dict instead of attribute: {attr}")
            _log.error(f"Skipping attribute process.")
            return False

        return attr

    def get_event(
        self,
        event_id: Union[str, int] = None,
    ):
        """Get Event by Event ID
        :param event_id: Event ID (int) or Event UUID (str)

        :returns: MISPEvent or False if failed
        """
        _log = self.logger
        try:
            event = self.misp.get_event(event_id, pythonify=True)
        except Exception as ex:
            _log.error(f"Error getting MISP event {event_id}", exc_info=True)
            _log.error(f"Skipping publication steps.")
            event = False
        return event

    def get_object(
        self,
        object_id: str = None,
    ):
        """Get Object by Object ID
        :param object_id: Object UUID (str)

        :returns: MISPObject or False if failed
        """
        _log = self.logger
        try:
            obj = self.misp.get_object(object_id, pythonify=True)
        except Exception as ex:
            _log.error(f"Error getting MISP object {object_id}", exc_info=True)
            obj = False
        return obj

    def publish_event(
        self,
        event_id: Union[int, str] = None,
    ):
        """Publishes selected MISP Event
        :param event_id: Event ID (int) or Event UUID (str)

        :returns: True/False
        """
        _log = self.logger
        _log.debug(f"PUBLISHING EVENT!")
        if self.test_run:
            _log.debug(f"Test Data Enabled. Not publishing event {event_id}.")
            return True
        try:
            self.misp.publish(event_id)
        except Exception as ex:
            _log.error(f"Error publishing event {event_id}", exc_info=True)
            _log.error(f"Manual re-publish required.")
            return False
        return True

    def search_attributes(
        self,
        **kwargs
    ):
        """Search for MISP Attributes via controller='attributes'
        :param **kwargs: Any arguments accepted by the PyMISP search attributes
            controller.

        :returns: List of found MISPAttributes
        """
        _log = self.logger
        _log.debug(f"Searching MISP attributes using following arguments: {kwargs}...")
        try:
            attributes = self.misp.search(controller='attributes', pythonify=True, **kwargs)
        except Exception as ex:
            _log.error(f"Error searching MISP for attributes", exc_info=True)
            return False
        _log.info(f"Found {len(attributes)} existing attributes for {kwargs}!")
        return attributes

    def search_attributes_tags(
        self,
        tags: list[str] = [],
    ):
        """Search for Attributes matching specific tags
        :param tags: List of tag strings (I think list of MISPTag might work too)
        :returns: List of MISPAttributes
        """
        _log = self.logger
        _log.debug(f"Searching MISP for existing attributes of with tags {tags}...")
        try:
            attrs = self.misp.search(controller='attributes', tags=tags,
                                    pythonify=True)
        except Exception as ex:
            _log.error(f"Error searching MISP for {tags}", exc_info=True)
            return False
        _log.info(f"Found {len(attrs)} existing attributes for {tags}!")
        return attrs

    def search_attributes_value(
        self,
        value: str = None,
    ):
        """Search MISP Attributes by Value
        :param value: String value to search for

        :returns: List of matching MISPAttributes
        """
        _log = self.logger
        _log.debug(f"Searching MISP for existing attributes of {value}...")
        try:
            attrs = self.misp.search(controller='attributes', value=value,
                                    pythonify=True)
        except Exception as ex:
            _log.error(f"Error searching MISP for {value}", exc_info=True)
            return False
        _log.info(f"Found {len(attrs)} existing attributes for {value}!")
        return attrs

    def search_events(
        self,
        **kwargs
    ):
        """Search for MISP Events via controller='events'
        :param **kwargs: Any arguments accepted by the PyMISP search attributes
            controller.

        :returns: List of matching MISPEvents
        """
        _log = self.logger
        _log.debug(f"Searching MISP events using following arguments: {kwargs}...")
        try:
            events = self.misp.search(controller='events', pythonify=True, **kwargs)
        except Exception as ex:
            _log.error(f"Error searching MISP for events", exc_info=True)
            return False
        _log.info(f"Found {len(events)} existing events for {kwargs}!")
        return events


    ############################################################################
    #### Advanced MISP Functions
    ############################################################################

    def strip_attributes(
        self,
        obj: MISPObject = None,
        obj_rels: list[str] = [],
    ):
        """Strip specific attributes from a MISP Object
        Used for operations like sanitizing an object before moving it to another
        instance, this function retains the original object, but strips any
        specified object relations that are undesirable - things like internal
        comments, PII, or other sensitive info.

        :param obj: MISPObject to strip
        :param obj_rels: List of object relations to strip from the object

        :returns: MISPObject
        """
        _log = self.logger
        attr_counter = 0
        saved_attrs = []

        for attr in obj.Attribute:
            if attr.object_relation not in obj_rels:
                saved_attrs.append(attr)
            else:
                _log.debug(
                    f"Attribute {attr.value} has type {attr.object_relation}. "
                    f"Stripping from {obj}!"
                )
                attr_counter += 1

        obj.Attribute = saved_attrs
        _log.debug(f"Stripped {attr_counter} attributes from {obj}.")
        return obj

    def strip_attribute_tags(
        self,
        obj: MISPObject = None,
    ):
        """Strip all tags from a given object's attributes
        :param obj: MISPObject to strip tags from

        :returns: Tag-free MISPObject
        """
        _log = self.logger
        tag_counter = 0
        for attr in obj.Attribute:
            if hasattr(attr, 'AttributeTag'):
                if len(attr.AttributeTag) > 0:
                    for _ in attr.AttributeTag:
                        tag_counter += 1
                    attr.AttributeTag = []
        _log.debug(f"Scrubbed {tag_counter} tags from {obj}")
        return obj

    def strip_comments(
        self,
        obj: MISPObject = None,
    ):
        """Strip all comments from a MISPObject
        :param obj: MISPObject to strip comments from

        :returns: Comment-free MISPObject
        """
        _log = self.logger
        comment_counter = 0
        for attr in obj.Attribute:
            if hasattr(attr, "comment"):
                if attr['comment']:
                    _log.debug(
                        f"Found comment {attr['comment']} for {attr['value']}"
                    )
                    attr['comment'] = ''
                    comment_counter += 1
        _log.debug(f"Stripped {comment_counter} comments from {obj}")
        return obj

    def strip_template(
        self,
        obj: MISPObject = None,
    ):
        """Strip Templates from MISPObjects
        :param obj: MISPObject to strip templates from

        :returns: Template-free MISPObject
        """
        if hasattr(obj, "template_version") and obj.template_version:
            obj.template_version = ""
        return obj

    def refresh_object_uuids(
        self,
        obj: MISPObject = None,
    ):
        """Regenerate all UUIDs within a MISP Object
        Used for things like generating a new object from an old one, or getting
        around pesky "ThIs UuId AlReAdY ExIsTs" annoyances.

        :param obj: MISPObject to refresh the UUID's on
        :returns: UUID-refreshed MISP Object
        """
        if hasattr(obj, 'uuid'):
            obj.uuid = str(uuid.uuid4())
        if hasattr(obj, 'Attribute') and obj.Attribute:
            for attr in obj.Attribute:
                if hasattr(attr, 'uuid'):
                    attr.uuid = str(uuid.uuid4())
        return obj

    def tag_it(
        self,
        attr: Union[MISPAttribute, MISPEvent] = None,
        tag: str = None,
    ):
        """Tag a MISPAttribute

        :param attr: MISPAttribute to tag
        :param tag: String of the tag you want to create and apply to this attr

        :returns: True/False
        """
        _log = self.logger
        if hasattr(attr, 'Tag'):
            for t in attr.Tag:
                if t.name == tag:
                    _log.debug(
                        f"Attribute [{attr}] already has tag {tag}. Skipping!"
                    )
                    return True

        if self.test_run:
            _log.debug(f"Skipping tagging because test-run is enabled.")
            return True

        try:
            self.misp.tag(attr, tag)
        except Exception as ex:
            _log.error(
                f"Error occurred while trying to tag attribute {attr}",
                exc_info=True
            )
            return False
        return True

    def update_attribute(
        self,
        attr: MISPAttribute = None,
    ):
        """Update MISP Attribute with new Value/Type/Comment/etc.
        Update a MISP Attribute with new attributes based on its attr.id
        :param attr: MISPAttribute to update

        :returns: Updated MISPAttribute or False
        """
        _log = self.logger
        if self.test_run:
            _log.debug(f"Test Data Enabled. Not updating attr {attr.id}.")
            return attr
        try:
            attr = self.misp.update_attribute(attr, pythonify=True)
        except Exception as ex:
            _log.error(f"Error updating MISP attribute {attr.id}", exc_info=True)
            _log.error(f"Skipping further processing.")
            return False
        return attr

    def update_attr_first_last_seen(
        self,
        attr: MISPAttribute = None,
        first_seen: Optional[Union[str, datetime]] = None,
        last_seen: Optional[Union[str, datetime]] = None,
    ):
        """Update the first-seen and last-seen timestamps on a given attribute
        Sets the first_seen and last_seen properties for a given attribute if
            they haven't been set already. Also updates the last_seen timestamp
            to now.

        :param attr: MISPAttribute to update timestamps for
        :param first_seen: Explicitly define the first_seen to this field.
        :param last_seen: Explicitly define the last_seen to this field.

        :returns: Updated MISPAttribute
        """
        if not hasattr(attr, 'first_seen'):
            attr.first_seen = attr.timestamp
        if not hasattr(attr, 'last_seen'):
            attr.last_seen = attr.timestamp
        now = datetime.now()
        epoch = int(now.timestamp())
        if epoch > int(attr.last_seen.timestamp()):
            attr.last_seen = epoch
        if first_seen:
            attr.first_seen = format_date(first_seen)
        if last_seen:
            attr.last_seen = format_date(last_seen)
        return attr

    ############################################################################
    #### Conversion Functions (LEDHNTR Things -> MISP Stuff)
    ############################################################################

    def convert_things_to_attrs(
        self,
        things: list[Thing] = None,
        misp_attr_map: Optional[dict] = {},
        to_ids_map: Optional[dict] = {},
        correlation_map: Optional[dict] ={},
    ):
        """Convert all Thing Attributes to proper MISP Attributes
        Given a list of arbitrary Thing Objects, convert all the Attribute Things
        to proper MISP Attributes.

        :param things: List of Thing Objects
        :param misp_attr_map: Alternate Dictionary of MISP Attribute Maps.
            Defaults to self.misp_attr_map.
        :param to_ids_map: Alternate dictionary of which types should be mapped
            to_ids and which should not. Defaults to self.to_ids_map
        :param correlation_map: Alternate dictionary of which types should be
            correlated in the database, and which should not. Defaults
            to self.correlation_map

        :returns: List of MISPAttributes
        """
        _log = self.logger
        misp_attrs = []
        remaining_things = []
        misp_attr_map = misp_attr_map or self.misp_attr_map()
        to_ids_map = to_ids_map or self.to_ids_map()
        correlation_map = correlation_map or self.correlation_map()

        for thing in things:
            if not isinstance(thing, Attribute):
                continue
            misp_type = misp_attr_map.get(thing.label) or thing.label
            misp_attr = MISPAttribute()
            misp_attr.type = misp_type
            misp_attr.value = thing.value
            if misp_type in to_ids_map['yes']:
                misp_attr.to_ids=True
            elif misp_type in to_ids_map['no']:
                misp_attr.to_ids=False
            if misp_type in correlation_map['yes']:
                misp_attr.disable_correlation=False
            elif misp_type in correlation_map['no']:
                misp_attr.disable_correlation=True
            misp_attrs.append(misp_attr)

        return misp_attrs, remaining_things

    def format_title(
        self,
        things: list[Thing] = None,
        author: str = None,
    ):
        """Format title to fit standard `Author | Title` format
        Given a list of Things, find a Title thing. If it exists, properly format
        the value.

        :param things: List of things ot search for 'title' thing in
        :param author: Author to create to the format with

        :return: List of things with the properly modified 'title' thing
        """
        _log = self.logger
        final_things = []

        if not author:
            _log.error(f"Author requried for title formatting.")
            return things

        for thing in things:
            if thing.label == 'title':
                new_title = f"{author} | {thing.value}"
                new_attr = Attribute(label='title', value=new_title)
                final_things.append(new_attr)
            else:
                final_things.append(thing)

        return final_things

    def frame_event_from_things(
        self,
        things: list[Thing] = None,
        kwargs: Optional[dict] = {},
    ):
        """Build the frame of a MISPEvent from a list of Things
        Extracts Attribute Things like title, tag, date-published, etc. and
            builds a MISPEvent framework with the metadata.

        :param things: list of Things to comb for extraction
        :param kwargs: Optional dict to overwrite default kwargs

        :returns: MISPEvent, remaining_things
        """
        meta_map = self.misp_event_meta_map()
        tags = []

        kwargs = {
            'threat_level_id': 4,
            'analysis': 2,
            'distribution': 1,
        }

        remaining_things = []

        for thing in things:
            if thing.label in meta_map:
                if meta_map[thing.label] not in kwargs:
                    kwargs[meta_map[thing.label]] = thing.value
            elif thing.label == "tag":
                if thing.value not in tags:
                    tags.append(thing.value)
            else:
                remaining_things.append(thing)

        event = MISPEvent()
        for k, v in kwargs.items():
            event[k] = v
        for tag in tags:
            mt = MISPTag()
            mt.name = tag
            event.Tag.append(mt)

        return event, remaining_things

    def convert_things_to_objs(
        self,
        things: list[Thing] = None,
        label_template_map: Optional[dict] = {},
    ):
        """Convert Thing Entities to MISPObjects

        :param things: List of things to search for Entities in
        :param label_template_map: Custom dictionary of thing.label -> template
            name for mapping templates on the MISP server.

        :returns: List of MISPObjects and remaining Things not yet processed.
        """

        _log = self.logger
        misp_objects = []
        remaining_things = []

        # Attempt to fit object into existing template
        # If template does not exist, or connection error getting template, 
        #   create generic object with no template.

        for thing in things:
            if not isinstance(thing, Entity):
                remaining_things.append(thing)
                continue
            template = None
            obj = None
            if thing.label in label_template_map:
                obj_template_name = label_template_map[thing.label]
            else:
                obj_template_name = thing.label
            try:
                template = self.misp.get_raw_object_template(
                    obj_template_name,
                )
            except Exception as e:
                _log.error(f"Unable to get template for {thing.label}: {e}")
            if template.get('errors') and template['errors'][0]==404:
                _log.error(f"Object template for {thing.label} does not exist!")
                _log.error(f"Returning entity's attrs as individual attributes!")
                template = None
            if not template is None:
                obj = MISPObject(
                    obj_template_name, 
                    misp_objects_template_custom=template
                )
            if not obj:
                # object had no template. converting all sub-things into Attrs
                for attr in thing.has:
                    remaining_things.append(attr)
                continue

            # Convert ObjectAttributes into misp_attrs
            misp_attrs, rem_ths = self.convert_things_to_attrs(thing.has)
            remaining_things += rem_ths
            for attr in misp_attrs:
                obj_rel = None
                attr_type = None
                if attr.type in template['attributes']:
                    obj_rel = attr.type
                    attr_type = template['attributes'][attr.type]['misp-attribute']
                else:
                    for obrel, obrel_meta in template['attributes'].items():
                        if obrel_meta['misp-attribute'] == attr.type:
                            obj_rel = obrel
                            attr_type = attr.type
                        if obj_rel:
                            break
                if not obj_rel:
                    _log.debug(
                        f"Could not find matching attribute for {attr} in "
                        f"template {obj_template_name}. Skipping!"
                    )
                    continue
                obj.add_attribute(obj_rel, type=attr_type, value=attr.value)

            misp_objects.append(obj)


        return misp_objects, remaining_things

    def strip_html_from_text(
        self,
        things: list[Thing] = [],
        text_labels: list[str] = [],
    ):
        """Strip HTML tags from a blob of text
        :param things: List of things to hunt for the text in.
        :param text_labels: list of thing labels to strip HTML from.

        :returns: Original list of things, but now sans-HTML on the 
            specified labels.
        """
        _log = self.logger
        revised_things = []

        for thing in things:
            if not isinstance(thing, Attribute):
                revised_things.append(thing)
                continue
            thing_stripped = False
            for tl in text_labels:
                if thing.label == tl:
                    stripped = re.sub('<[^<]+?>', '', thing.value)
                    # _log.info(f"Stripped result: {stripped}")
                    new_attr = Attribute(label=tl, value=stripped)
                    revised_things.append(new_attr)
                    thing_stripped = True
                    break
            if not thing_stripped:
                revised_things.append(thing)

        return revised_things

    def extract_yara_rules(
        self,
        things: List[Thing] = [],
        html_labels: list[str] = [],
    ):
        """Extract YARA rules from full-HTML report

        :param things: list of Things to search through.
        :param html_labels: list of HTML thing.labels to extract YARA rules from

        :returns: List of MISPAttributes YARA rules.
        """
        _log = self.logger
        yara_rules = []

        YARA_PARSE_RE = re.compile(r"""
            (?:^|\s)
            (
                (?:
                    \s*?import\s+?"[^\r\n]*?[\r\n]+|
                    \s*?include\s+?"[^\r\n]*?[\r\n]+|
                    \s*?//[^\r\n]*[\r\n]+|
                    \s*?/\*.*?\*/\s*?
                )*
                (?:
                    \s*?private\s+|
                    \s*?global\s+
                )*
                rule\s*?
                \w+\s*?
                (?:
                    :[\s\w]+
                )?
                \s+\{
                .*?
                condition\s*?:
                .*?
                \s*\}
            )
            (?:$|\s)
        """, re.MULTILINE | re.DOTALL | re.VERBOSE)

        for thing in things:
            if thing.label not in html_labels:
                continue
            html = thing.value
            soup = BeautifulSoup(html, 'html.parser')
            plaintext = soup.get_text()
            plaintext = plaintext.replace(u'\xa0', u' ')
            yara_search = YARA_PARSE_RE.findall(plaintext)

            for ys in yara_search:
                attr = MISPAttribute()
                attr.type = 'yara'
                attr.category = 'Artifacts dropped'
                attr.value = ys
                attr.to_ids = False
                yara_rules.append(attr)

        return yara_rules

    ## TODO
    def custom_html2md(self, html, **options):
        return CustomConverter(**options).convert(html)

    # def convert_html_to_md(self,):
    def convert_html_to_md(
        self,
        things: list[Thing] = [],
        html_labels: list[str] = [],
    ):
        """Convert specified labels from HTML into Markdown

        :param things: list of Things to search through.
        :param html_labels: list of thing.labels to convert from HTML to MD

        :returns: Revised list of Things, with HTML converted to MD.
        """
        _log = self.logger
        revised_things = []

        for thing in things:
            if not isinstance(thing, Attribute):
                revised_things.append(thing)
                continue
            h2m_converted = False
            for hl in html_labels:
                if thing.label == hl:
                    # FIXME
                    # md = thing.value
                    mdres = self.custom_html2md(thing.value)
                    new_attr = Attribute(label=hl, value=mdres)
                    revised_things.append(new_attr)
                    h2m_converted = True
                    break
            if not h2m_converted:
                revised_things.append(thing)

        return revised_things

    #### TODO LongTerm

    def convert_relations_to_event(
        self,
        things: list[Thing] = []
    ):
        """Convert Thing Relations to MISPEvents
        """
        misp_events = []
        return misp_events