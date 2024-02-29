"""
Overview
========

This is a connector plugin for saving infrastructure Things in flat JSON files.

"""

import copy
import dateutil.parser
import json
import logging
import os
import re

from datetime import datetime, timezone
from pathlib import Path
from pkg_resources import resource_stream
from pprint import pformat

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
    Role,
    Query
)
from ledhntr.helpers import LEDConfigParser
from ledhntr.helpers import format_date, diff_entities, diff_relations, dumps
from ledhntr.plugins.connector import ConnectorPlugin

class JSONFlatsClient(ConnectorPlugin):
    """
    JSONFlatsClient

    """
    def __init__(
        self,
        config:LEDConfigParser,
        logger: Optional[logging.Logger] = None,
        path: Optional[str] = None,
    ) -> None:
        super().__init__(config)

        if not logger:
            self.logger: logging.Logger = logging.getLogger('ledhntr')
        _log = self.logger
        self.config = config
        if not path:
            path = config.get(
                'options',
                'path',
                fallback = './data/jsonflats/dbs/',
            )
        if not path.endswith('/'):
            path += '/'

        self.db_name = config.get(
            'options',
            'db_name',
            fallback = 'dev_db',
        )

        self.client = None
        self.session = None
        # Transactions in this case will correlate to the full path we're saving
        # flat JSON files to. (e.g. ~/.ledhntr/data/jsonflats/dbs/20221101_TrashPanda_TTP1)
        # self.tx = self.check_tx()

        self.schema = self.parse_schema_file()
        self.thing_keys = self.get_thing_keys()

        # adding debug flag for doing things like making sure we always print
        # the resulting ledid of a newly-added Thing
        self.debug = False

    def set_client(
        self,
        client: ConnectorPlugin,
    ):
        """Set client for interacting with a file system
        :params client: This is a ConnectorPlugin used for writing to a file
            system (e.g. local storage vs AWS S3)
        """
        _log = self.logger
        client.db_name = self.db_name
        self.client = client
        return self.client

    def add_thing(
        self,
        thing: Thing = None,
        dedup_ignore_players: Optional[bool] = False,
        force: Optional[bool] = False,
        return_things: Optional[bool] = False,
    ):
        """Add a Thing to the flat JSON collection

        :param thing: Thing object to add to the JSON collection
        :param dedup_ignore_players: Ignore players when checking if thing exists
        :param force: Force adding this thing even if it exists already
        :param return_things: Return newly added things

        :returns: Defaults to boolean unless return_things param == True
        """
        _log = self.logger
        if not force:
            existing_thing = False
            existing_things = self.check_thing_exists(
                thing,
                dedup_ignore_players = dedup_ignore_players,
            )
            if existing_things:
                if isinstance(existing_things, list):
                    existing_thing=existing_things[0]
                    if len(existing_things) > 1:
                        _log.warning(f"Apparently there are multiple existing things...")
                        _log.warning(pformat(existing_things))
                        _log.warning(f"Grabbing the first one!")
                else:
                    existing_thing = existing_things

        if existing_thing:
            _log.debug(f"Looks like {thing} already exists!")
            _log.debug(f"Adding any new details, but not removing any...")
            updated_thing = self.update_thing(
                new_thing=thing, old_thing=existing_thing,
                return_things=return_things
            )
            if not return_things:
                return True
            else:
                return updated_thing

        if isinstance(thing, Attribute):
            result = self.client.write_thing(thing, return_things=return_things)
        elif isinstance(thing, Entity):
            if not self.db_name=='road' and not thing.get_attributes('confidence'):
                con = Attribute(label='confidence', value=0.0)
                thing.has.append(con)
            if not thing.get_attributes('date-discovered'):
                now = datetime.now(timezone.utc)
                dd = Attribute(label='date-discovered', value=now)
                thing.has.append(dd)
            result = self.client.write_thing(thing, return_things=return_things)
        elif isinstance(thing, Relation):
            if not self.db_name=='road' and not thing.get_attributes('confidence'):
                con = Attribute(label='confidence', value=0.0)
                thing.has.append(con)
            if not thing.get_attributes('date-discovered'):
                now = datetime.now(timezone.utc)
                dd = Attribute(label='date-discovered', value=now)
                thing.has.append(dd)
            result = self.client.write_thing(thing, return_things=return_things)
        else:
            _log.error(f"Unknown thing passed: {type(thing)} - {thing}")
            return False

        return result

    def check_thing_exists(
        self,
        thing: Thing = None,
        dedup_ignore_players: Optional[bool] = False,
    ):
        """
        Check if a given thing exists. If it doesn't, return False. If it does,
        return the full thing.
        """
        _log = self.logger
        _log.debug(f"Checking if thing {thing} exists...")

        # Strip things likely to be different between a new thing and
        # an existing thing

        search_thing = copy.deepcopy(thing)
        include_meta_attrs = False # include_meta_attrs defaults to False. HOWEVER,
        # There are some cases where a keyattr might be a meta_attr (like a hunt-name).
        # and in those cases, we HAVE to make sure include_meta_attrs = True.

        # If a thing has a key attribute, that's the only thing we want
        # to search on - everything else gets in the way
        if not self.thing_keys:
            self.get_thing_keys()
        keyattr_thing = False
        if thing.label in self.thing_keys:
            keyattr_thing = True
            key_label = self.thing_keys[thing.label]
            if key_label in thing.meta_attrs:
                include_meta_attrs = True
            thing.keyattr = key_label
            for attr in thing.has:
                if attr.label!=key_label:
                    search_thing.has.remove(attr)
            if hasattr(search_thing, 'players'):
                # We just want the key attribute - players make it messy
                search_thing.players = {}

        # If we already have a keyattr thing, skip all this mess.
        # We already have the key we need.
        if not keyattr_thing:
            if isinstance(thing, Entity) or isinstance(thing, Relation):
                for attr in thing.has:
                    if attr.label in thing.meta_attrs:
                        if attr in search_thing.has:
                            search_thing.has.remove(attr)

            if isinstance(thing, Relation):
                # Ignore players for things like geoloc
                if thing.label in thing.eq_ignore_players:
                    search_thing.players = {}
                    thing.players = {}

            if hasattr(thing, 'players') and thing.players:
                search_thing.players = {}
                if dedup_ignore_players:
                    search_thing.players = {}
                    thing.players = {}
                else:
                    for role, players in thing.players.items():
                        for player in players:
                            player_copy = copy.deepcopy(player)
                            player_copy.has = []
                            for attr in player.has:
                                if attr.label in thing.meta_attrs:
                                    continue
                                player_copy.has.append(attr)
                            # If this is a USELESS player, we don't want to include
                            # it in our search_thing.
                            if player_copy.has:
                                if role not in search_thing.players:
                                    search_thing.players[role] = [player_copy]
                                else:
                                    search_thing.players[role].append(player_copy)

        _log.debug(f"Searching for existing thing...")
        remote_thing = self.find_things(
            search_thing,
            include_meta_attrs=include_meta_attrs,
        )
        if not remote_thing:
            _log.debug(f"Nothing found!")
            return False
        if len(remote_thing) > 1:
            _log.warning(f"Uh oh.. We searched for {search_thing} and got more than one result!")
            _log.warning(f"search_thing: {search_thing.to_dict()}")

        return remote_thing

    def check_tx(
        self,
        path: Optional[str] = '',
        db_name: Optional[str] = None,
    ):
        """Sets self.tx to the full path of this flat JSON collection
        """
        _log = self.logger

        db_name = db_name or self.db_name
        if not db_name:
            _log.error(f"db_name required to set transaction!")
            return False

        self.tx = self.client.set_path(path=path, db_name=db_name)
        return self.tx

    def create_transaction(
        self,
        path: Optional[str] = '',
        db_name: Optional[str] = None,
    ):
        """Redundant to check_tx but kept in for compatibility reasons
        :param db_name: Name of the folder to dive into
        :returns: str of full path to walk
        """
        return self.check_tx(path=path, db_name=db_name)

    def find_things(
        self,
        things: Union[List[Thing], Thing] = [],
        db_name: Optional[str] = "",
        search_mode: Optional[str] = "full",
        limit_get: Optional[bool] = True,
        include_meta_attrs: Optional[bool] = False,
    ):
        """Find things in a flat directory structure

        :param things: List of Thing objects to search for
        :param db_name: Optional db name to search
        :param search_mode: While this is important for speeding up searches in
            TypeDB, I'm not sure that it's all that important when using JSON flats.
        :param limit_get: Pretty sure this isn't necessary for this client, but
            keeping it in here for compatibility purposes at the moment.
        :param include_meta_attrs: By Default meta attributes like first-seen are
            not included in search matching. If this is set to True, meta attributes
            will be explicitly searched for.

        :returns: List of Things (search_results)
        """
        _log = self.logger
        search_results = []

        if not db_name:
            db_name = self.db_name

        self.check_tx(db_name=db_name)

        if not isinstance(things, list):
            things = [things]

        search_things = []
        for thing in things:
            if hasattr(thing, 'keyattr'):
                if not thing.keyattr:
                    if thing.label in self.thing_keys:
                        thing.keyattr = self.thing_keys[thing.label]
            safe_copy = copy.deepcopy(thing)
            if isinstance(thing, Relation):
                # If this is a type of Relation where we want to ignore the players
                # attached to it (e.g. geoloc or hunt), make sure we strip the players.
                if thing.label in thing.eq_ignore_players:
                    safe_copy.players = {}
                else:
                    # If we're taking the players into account, make sure each
                    # player has meta attributes (e.g. first-seen) scrubbed from
                    # it before sending to find_things
                    if not include_meta_attrs:
                        for role, players in thing.players.items():
                            updated_players = []
                            for player in players:
                                safe_player = copy.deepcopy(player)
                                for attr in player.has:
                                    if attr.label in thing.meta_attrs:
                                        # NOTE - UNLESS one of those meta attributes is
                                        # also the keyattr!
                                        if hasattr(safe_player, 'keyattr') \
                                        and attr.label != safe_player.keyattr:
                                            safe_player.has.remove(attr)
                                updated_players.append(safe_player)
                            safe_copy.players[role] = updated_players
            if not include_meta_attrs:
                if hasattr(thing, 'has'):
                    # For Relations and Entities, make sure meta attributes such as
                    # date-seen, note, and tag are not included in the search
                    for attr in thing.has:
                        if attr.label in thing.meta_attrs:
                            # NOTE - UNLESS one of those meta attributes is
                            # also the keyattr!
                            if hasattr(thing, 'keyattr') and attr.label != thing.keyattr:
                                safe_copy.has.remove(attr)
            search_things.append(safe_copy)

            # Query Things
            _log.debug(f"Searching for things {search_things}")
            final_query = False
            for thing in search_things:
                # full_dir = os.path.join(self.path, db_name)
                # self.tx = os.path.abspath(full_dir)
                if isinstance(thing, Attribute):
                    continue
                if not thing.label:
                    continue

                search_path = self.client.get_search_path(self.tx, thing.label)

                _log.debug(f"search_path: {search_path}")
                file_list = self.client.list_dir(search_path)
                _log.debug(f"file_list:\n{pformat(file_list)}")
                if not file_list:
                    _log.debug(f"No files found for type {thing.label}!")
                    continue
                for f in file_list:
                    dir_file = os.path.split(f)
                    d = dir_file[0]
                    filename = dir_file[1]
                    if thing.keyval:
                        if filename.startswith(f"{thing.keyval}-"):
                            json_data = self.client.load_json(f)
                        else:
                            continue
                        '''
                    elif thing.ledid:
                        if filename.endswith(f"-{thing.ledid}.json"):
                            json_data = self.load_json(f)
                            if 'thingtype' in json_data and json_data['thingtype']:
                                rebuilt_thing = None
                                if json_data['thingtype'] == 'entity':
                                    ent = Entity()
                                    rebuilt_thing = ent.from_dict(**json_data)
                                elif json_data['thingtype'] == 'relation':
                                    rel = Relation()
                                    rebuilt_thing = rel.from_dict(**json_data)
                                if rebuilt_thing:
                                    search_results.append(rebuilt_thing)
                                    return search_results
                        else:
                            continue
                        '''
                    else:
                        json_data = self.client.load_json(f)

                    if 'thingtype' in json_data and json_data['thingtype']:
                        if json_data['thingtype'] == 'entity':
                            ent = Entity()
                            rebuilt_thing = ent.from_dict(**json_data)
                        elif json_data['thingtype'] == 'relation':
                            rel = Relation()
                            rebuilt_thing = rel.from_dict(**json_data)
                        _log.debug(f"rebuilt_thing: {rebuilt_thing}")
                        _log.debug(pformat(rebuilt_thing.to_dict()))

                        if rebuilt_thing == thing and rebuilt_thing not in search_results:
                            search_results.append(rebuilt_thing)
                            continue
                        matching = True
                        if hasattr(thing, 'has') and thing.has:
                            for attr in thing.has:
                                if attr in thing.meta_attrs and not include_meta_attrs:
                                    continue
                                # TODO - revisit this at some point. sometimes attr.value would be False
                                # and that's explicitly what we want
                                if not attr.value:
                                    continue
                                if attr.label == 'ledid':
                                    continue
                                if attr not in rebuilt_thing.has:
                                    matching=False
                                    _log.debug(f"attr {attr} not in rebuilt_thing: {rebuilt_thing.has}")
                        if hasattr(thing, 'players') and thing.players:
                            for role, players in thing.players.items():
                                if role not in rebuilt_thing.players:
                                    _log.info(f"{role} not in {rebuilt_thing.players}")
                                    rebuilt_thing.players[role]=[]
                                for player in players:
                                    if player not in rebuilt_thing.players[role]:
                                        matching=False
                                        _log.debug(f"player {player} not in rebuilt_thing.players: {rebuilt_thing.players}")
                        if matching and rebuilt_thing not in search_results:
                            search_results.append(rebuilt_thing)
                    else:
                        _log.error(f"{f} is an invalid Thing object!")
                        _log.debug(f"{f} json-loaded content:\n{pformat(json_data)}")

            return search_results

    def get_thing_keys(
        self,
    ):
        """Get key attributes for all Things

        :returns: Dict {'label': 'key-attribute-label'}
        """
        _log = self.logger
        thing_keys = {}

        for ent in self.schema['entity']:
            if ent.keyattr:
                if ent.label not in thing_keys:
                    thing_keys[ent.label] = ent.keyattr

        for rel in self.schema['relation']:
            if rel.keyattr:
                if rel.label not in thing_keys:
                    thing_keys[rel.label] = rel.keyattr

        self.thing_keys = thing_keys
        return self.thing_keys

    def parse_schema_file(
        self,
        schema: Optional[str] = "",
    ):
        """Manually parses schema files

        Manually parses schema.tql files so things like keyattrs can be read
        without needing a specific database to read the results from.

        :param schema: string location of targeted schema.tql file.
        :returns: dict of 'attributes', 'entities', and 'relations'
        """
        _log = self.logger
        if not schema:
            schema = resource_stream('ledhntr', 'schemas/schema.tql').name

        thing_objs = {
            'attribute': [],
            'entity': [],
            'relation': [],
        }

        thing_types = {
            'attribute': ['attribute'],
            'entity': ['entity'],
            'relation': ['relation'],
        }

        with open(schema, 'r') as s:
            data = s.read()

        pattern = r"(?s)([a-z0-9\-]+\s+sub.*?);"
        things = re.findall(pattern, data)
        type_parsing = copy.deepcopy(things)

        role_pattern = r"(?s)relates\s+([a-z0-9\-]+)\s*(,|$)"
        attr_pattern = r"(?s)owns\s+([a-z0-9\-]+)\s*(@|,|$)"
        keyattr_pattern = r"(?s)owns\s+([a-z0-9\-]+)\s*@key"

        re_role = re.compile(role_pattern)
        re_attr = re.compile(attr_pattern)
        re_keyattr = re.compile(keyattr_pattern)

        counter = 1
        _log.debug(f"Attempting to parse schema {schema}...")
        while type_parsing and counter < 5:
            _log.debug(f"\nStarting loop # {counter}")
            _log.debug(f"unparsed types left: {len(type_parsing)}")
            safe_thing_types = copy.deepcopy(thing_types)
            for key, types in safe_thing_types.items():
                for t in types:
                    label_pattern = rf"(?s)([a-z0-9\-]+)\s+sub\s+({t})"
                    re_label = re.compile(label_pattern)
                    safe_type_parsing = copy.deepcopy(type_parsing)
                    for thing in safe_type_parsing:
                        res = re_label.search(thing)
                        # match = [<full_string>, <new_label>, <existing_label>]
                        if res:
                            # Get Label
                            label = res[1]
                            parent_label = res[2]
                            if label not in thing_types[key]:
                                thing_types[key].append(label)

                            # Get Roles
                            found_roles = re_role.findall(thing)
                            roles = []
                            for fr in found_roles:
                                if fr[0] not in roles:
                                    roles.append(fr[0])

                            # Get Attributes
                            found_attributes = re_attr.findall(thing)
                            attributes = []
                            for fa in found_attributes:
                                if fa[0] not in attributes:
                                    attributes.append(fa[0])

                            # Get KeyAttr
                            found_keyattr = re_keyattr.search(thing)
                            keyattr = None
                            if found_keyattr:
                                keyattr = found_keyattr[1]

                            # Get Plays - TODO
                            '''
                            Maybe I'll care about this at some point, but right now I honestly
                            just started this whole parsing thing in order to get the keyattrs
                            without having to connect to a DB.

                            In order to parse plays correctly there would have to be a lot
                            of cycling through thing_objects in order to match and object
                            type with its players, and that's not something I feel like
                            wasting time on at the moment.
                            '''

                            # Convert to Thing object
                            th = None
                            if parent_label == 'attribute':
                                th = Attribute(label=label)
                            elif parent_label == 'entity':
                                th = Entity(label=label)
                            elif parent_label == 'relation':
                                th = Relation(label=label)
                            else:
                                for _, tos in thing_objs.items():
                                    for to in tos:
                                        if to.label==parent_label:
                                            th = copy.deepcopy(to)
                                            del th.ledid
                                th._label=label
                            if th is None:
                                _log.debug(
                                    f"No viable parent label ({parent_label}) found for "
                                    f"new thing label {label}. Skipping!"
                                )
                                continue

                            for attribute in attributes:
                                attr = Attribute(label=attribute)
                                if attr not in th.has:
                                    th.has.append(attr)

                            if keyattr:
                                th.keyattr = keyattr

                            for role in roles:
                                if role not in th.players:
                                    th.players[role] = []

                            # purge ledid
                            if isinstance(thing, (Entity, Relation)):
                                del th.ledid

                            if th not in thing_objs[key]:
                                thing_objs[key].append(th)

                            # Mark this thing as already parsed
                            if thing not in type_parsing:
                                _log.error(f"Thing not in type_parsing:")
                                _log.error(pformat(thing))

                            type_parsing.remove(thing)
            _log.debug(f"unparsed types left: {len(type_parsing)}")
            counter += 1
            if counter > 10:
                _log.error(
                    f"It should not take more than 10 iterations to processes a schema."
                    f" Check your schema layout and try that again..."
                )
                break

        return thing_objs

    def attach_attribute(
        self,
        old_thing,
        attr,
        return_things: Optional[bool] = False,
    ):
        _log = self.logger
        _log.debug(f"Attaching {attr} to {old_thing}")
        result = True

        new_thing = self.find_things(old_thing)[0]
        if attr not in new_thing.has:
            new_thing.has.append(attr)
            result = self.client.write_thing(new_thing, return_things=return_things)
        else:
            _log.info(f"Attribute {attr} already exists!")
            if return_things:
                result = new_thing

        return result

    def detach_attribute(
        self,
        old_thing,
        attr,
        return_things: Optional[bool] = False,
    ):
        _log = self.logger
        _log.debug(f"Detaching {attr} from {old_thing}")
        result = True

        new_thing = self.find_things(old_thing)[0]
        if attr in new_thing.has:
            new_thing.has.remove(attr)
            result = self.client.write_thing(new_thing, return_things=return_things)
        else:
            _log.info(f"Attribute {attr} already missing from {new_thing}!")
            if return_things:
                result = new_thing

        return result

    def replace_attribute(
        self,
        thing: Thing = None,
        new_attr: Attribute = None,
        ledid: Optional[str] = "",
    ):
        """Replace all new_attr.label attributes Thing has with new_attr
        Given a Thing that has new_attr.label Attribute types attached to it,
            replace those attributes with new_attr instead.
        :param thing: Entity or Relation to modify
        :param new_attr: New attribute to attach to Entity or Relation that
            also dictates which existing attribute types/labels to remove.
        :param ledid: If specified, only replaces the Attribute corresponding
            to this particular ledid.

        :returns: Updated Thing object
        """
        _log = self.logger
        label = new_attr.label
        safe_copy = copy.deepcopy(thing)

        # Remove old attributes we want to replace
        for attr in safe_copy.has:
            if ledid and attr.ledid!=ledid:
                continue
            if attr.label == label:
                try:
                    self.detach_attribute(
                        old_thing = thing,
                        attr = attr,
                    )
                except Exception as e:
                    _log.error(f"Could not remove attribute {attr} from {thing}: {e}")
                    return False
                thing.has.remove(attr)

        # Add new attribute (but don't add blank attributes)
        if new_attr.value or new_attr.value == 0:
            try:
                self.attach_attribute(
                    old_thing=thing,
                    attr=new_attr,
                )
            except Exception as e:
                _log.error(f"Could not add attribute {new_attr} to {thing}: {e}")
                return False

        thing.has.append(new_attr)
        return thing

    def attach_player(
        self,
        old_thing,
        role,
        player,
        return_things: Optional[bool] = False,
    ):
        _log = self.logger
        _log.debug(f"Attaching {role} {player} to {old_thing}")
        result = True

        new_thing = self.find_things(old_thing)
        if new_thing:
            new_thing = new_thing[0]
        else:
            _log.debug(f"No existing version of {old_thing} found")
            new_thing = old_thing
        if role not in new_thing.players:
            new_thing.players[role] = []
        if player not in new_thing.players[role]:
            new_thing.players[role].append(player)
            result = self.client.write_thing(new_thing, return_things=return_things)
        else:
            _log.info(f"Player {player} already exists in {role}!")
            if return_things:
                result = new_thing

        return result

    def detach_player(
        self,
        old_thing,
        role,
        player,
        return_things: Optional[bool] = False,
    ):
        _log = self.logger
        _log.debug(f"Detaching {role} {player} from {old_thing}")
        result = True

        new_thing = self.find_things(old_thing)
        if new_thing:
            new_thing = new_thing[0]
        else:
            _log.debug(f"No existing version of {old_thing} found")
            new_thing = old_thing
        if role not in new_thing.players:
            _log.info(f"No {role} role in {old_thing}")
            if return_things:
                result = new_thing
            new_thing.players[role] = []
        if player in new_thing.players[role]:
            new_thing.players[role].remove(player)
            result = self.client.write_thing(new_thing, return_things=return_things)
        else:
            _log.info(f"Player {player} doesn't exist in {role} of {new_thing}!")
            if return_things:
                result = new_thing

        return result

    #### TODO ####

    def bulk_add(
        self,
        things: Dict = {},
        force: Optional[bool] = False,
    ):
        """Used for adding things to the database in bulk

        :param things: A dictionary of things. Must have keys in this format:
            things = {
                'attributes': [<Attrib1>, <Attrib2>],
                'entities': [<Ent1>, <Ent2>],
                'relations': [<Rel1>],
            }

        :param force: Whether or not to skip checking if the things already exist.
            NOTE - If a Thing has a key attribute associated with it, it will
            still be checked in order to avoid conflicts in the database.
        """
        _log = self.logger
        _log = self.logger
        _log.info(f"Starting bulk_add process...")
        _log.debug(f"{pformat(things)}")
        if 'attributes' in things:
            if len(things['attributes']) > 0:
                # probably should set include_meta_attrs = True here
                # otherwise they'll just always add "new" ones
                _log.info(f"Processing {len(things['attributes'])} attributes...")
                self.bulk_add_update(
                    things=things['attributes'],
                    include_meta_attrs=True,
                    force=force,
                )
        if 'entities' in things:
            if len(things['entities']) > 0:
                _log.info(f"Processing {len(things['entities'])} entities...")
                self.bulk_add_update(things=things['entities'], force=force)
        if 'relations' in things:
            if len(things['relations']) > 0:
                _log.info(f"Processing {len(things['relations'])} relations...")
                self.bulk_add_update(things=things['relations'], force=force)
        _log.info(f"Finished updating things!")

        return True

    def bulk_add_update(
        self,
        things: List[Thing] = [],
        force: Optional[bool] = False,
        include_meta_attrs: Optional[bool] = False,
    ):
        """Add items in bulk or update existing items
        This was added for compatibility reasons and doesn't really apply to 
        storing flat JSON files.
        """
        _log = self.logger
        _log.info(f"Starting bulk_update add with {len(things)} things!")

        for thing in things:
            self.add_thing(thing, force=force)

        # TODO - This still needs work. It might half-assed work for now though.

        return True

    def update_thing(
        self,
        new_thing: Thing = None,
        old_thing: Optional[Thing] = None,
        return_things: Optional[Thing] = False,
    ):
        """
        Given a "new thing" - check the database for existing thing and apply
            any changes between the two.

            :param old_thing: Existing, remote thing - only use this if you're
                passing it a FULL representation of that Thing and not a 'lite'
                version of it.
        """

        # NOTE - Originally I was going to use this for adding and deleting stuff
        #    but I found it safer just to only add Things to existing Things,
        #    rather than do a full diff and trust that the new thing is "more right".

        _log = self.logger
        blank_thing = copy.deepcopy(Thing())

        if old_thing:
            old_thing = self.find_things(old_thing)[0]

            # By using merge() we're only adding new stuff from the new_thing,
            # rather than removing things that are missing.
            # Also worth noting, merge() has checks to make sure we don't replace
            # pre-existing 'first-seen', 'last-seen', 'ledid', 'confidence',
            # or 'date-discovered' (see merge() functions in data_classes.py)
            old_copy = copy.deepcopy(old_thing)
            new_thing = old_copy.merge(**new_thing)

        if not new_thing.ledid:
            _log.warning(
                f"Cannot update thing without LEDID! Did you mean to "
                f"add_thing instead?"
            )
            return False

        blank_thing.ledid = new_thing.ledid
        if not old_thing:
            find_thing_res = self.find_things(
                blank_thing,
            )
            if isinstance(find_thing_res, list) and find_thing_res:
                if len(find_thing_res) > 1:
                    _log.warning(
                        f"There were {len(find_thing_res)} things that matched!"
                    )
                    _log.warning(f"Using first thing: {find_thing_res[0]}")
                old_thing = self.find_things(find_thing_res[0])[0]
            elif find_thing_res:
                old_thing = self.find_things(find_thing_res)[0]
        if not old_thing:
            _log.error(
                f"Unable to find existing thing with ledid {blank_thing.ledid}."
                f"Cannot update an object that doesn't exist!"
            )
            return False

        # Get all the changes
        _log.debug(f"old_thing: {pformat(old_thing.to_dict())}")
        _log.debug(f"new_thing: {pformat(new_thing.to_dict())}")

        if isinstance(new_thing, Entity):
            diff_results = diff_entities(self, old_thing, new_thing)
        elif isinstance(new_thing, Relation):
            diff_results = diff_relations(self, old_thing, new_thing)
        else:
            _log.warning(
                f"{new_thing} is a {type(new_thing)} and cannot be updated."
                f" Returning existing thing: {old_thing}."
            )
            return old_thing

        if not diff_results:
            _log.error(
                f"Error running diff results! "
                f"Returning existing thing {old_thing}"
            )
            return old_thing

        if diff_results['equal']==True:
            _log.debug(f"new thing and old thing are equal!")
            _log.debug(f"\tnew_thing: {new_thing}")
            _log.debug(f"\told_thing: {old_thing}")
            return old_thing

        updated = False
        _log.debug(f"old_thing: {pformat(old_thing.to_dict())}")
        _log.debug(f"new_thing: {pformat(new_thing.to_dict())}")
        _log.debug(f"All diff_results: {pformat(diff_results)}")
        if diff_results['add_has']:
            for attr in diff_results['add_has']:
                self.add_thing(attr, return_things=False)
                self.attach_attribute(old_thing, attr, return_things=False)
                updated = True

        if 'add_players' in diff_results:
            if diff_results['add_players']:
                for role, players in diff_results['add_players'].items():
                    for player in players:
                        self.attach_player(
                            old_thing, role, player, return_things=False
                        )
                        updated = True

        if not updated:
            _log.debug(
                f"Even though diff_results weren't equal we didn't apply"
                f"any updates... returning old_thing. diff_results: "
                f"{pformat(diff_results)}"
            )
            return old_thing

        # Get final updated thing
        # newest_thing = self.find_things(blank_thing)[0]
        newest_thing = self.find_things(old_thing)[0]
        _log.debug(f"updated_thing: {newest_thing}")

        # Scrub empty entities used for creating base-line relations
        if hasattr(newest_thing, 'players'):
            if newest_thing.players:
                if len(newest_thing.players) > 1:
                    safe_copy = copy.deepcopy(newest_thing.players)
                    for role, players in safe_copy.items():
                        for player in players:
                            if player.label == 'empty-ent':
                                self.detach_player(
                                    newest_thing,
                                    role,
                                    player,
                                    return_things=False
                                )
                                newest_thing = self.find_things(blank_thing)[0]
        if return_things:
            return newest_thing
        else:
            return True