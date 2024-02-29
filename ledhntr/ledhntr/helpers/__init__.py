import dateutil.parser
import logging, logging.handlers
import json

from configparser import ConfigParser
from datetime import datetime, timezone
from itertools import chain, starmap
from pprint import pformat
from typing import Any, Optional, Dict, DefaultDict, Union, List

from ..data_classes import Attribute, Relation, Entity, Query
# from ..plugins.connector import ConnectorPlugin

class LEDConfigParser(ConfigParser):
    """
    Extends ConfigParser to simplfy handling of common configuration options
    """

    def getlist(self, section, option, *args, **kwargs):
        """
        Create a `list()` from `ConfigParser` option using comma delimited string
        """
        value = self.get(section, option, fallback=kwargs.get('fallback', ''))
        if isinstance(value, list):
            return value
        return [o.strip() for o in value.split(',') if o]

    def getset(self, section, option, *args, **kwargs):
        """
        Create a `set()` from `ConfigParser` option using comma delimited string
        """
        value = self.get(section, option, fallback=kwargs.get('fallback', ''))
        if isinstance(value, set):
            return value
        return set(o.strip() for o in value.split(',') if o)

    def getjson(self, section, option, *args, **kwargs) -> Union[Dict, List]:
        """
        Create a Python object from `ConfigParser` option using JSON syntax
        no fallback returns an empty dictionary
        """
        value = self.get(section, option, fallback=kwargs.get('fallback', {}))
        if isinstance(value, (dict, list)):
            return value
        return json.loads(value)

class JsonComplexEncoder(json.JSONEncoder):
    """
    Extends the default JSON encoder to handle bytes, sets, and datetime
    """

    def default(self, o) -> Any:
        if isinstance(o, bytes):
            return UnicodeDammit(o).unicode_markup  # type: ignore
        elif isinstance(o, datetime):
            return str(o)
        elif isinstance(o, set):
            return list(o)
        try:
            return vars(o)
        except Exception:
            pass
        return json.JSONEncoder.default(self, o)

def convert_dict_to_thing(led, d):
    _log = led.logger
    if 'Attribute' in d:
        attr = Attribute()
        attr.from_dict(**d)
        thing = attr
    elif 'Entity' in d:
        ent = Entity()
        ent.from_dict(**d)
        thing = ent
    elif 'Relation' in d:
        rel = Relation()
        rel.from_dict(**d)
        thing = rel
    else:
        _log.error(
            f"Thing dictionary did not have a valid key! "
            f"\n\t{thing.keys()}\n\t"
            f"Expected Attribute, Entity, or Relation"
        )
        return False
    _log.debug(f"Converted Dict thing to {thing}")
    return thing

def format_date(
    date_input: Union[str,datetime] = "",
):
    """
    Given either an ambiguous datetime string or a datetime object, convert
    it to a uniform format and return a datetime object.

    :param date_string: date string in any format, or datetime object

    :returns: datetime object - if unsuccessful returns dto of epoch 404404404
    """

    conversion_success = False

    if isinstance(date_input, int) or isinstance(date_input, float):
        # split it to account for microseconds and other BS
        # This isn't perfect, but should account for some mistakes.
        sdi = str(date_input).split(".")[0]
        if len(sdi)>10: # you'll have to fix this bug in Nov 2286 ;)
            sdi = sdi[0:10]
        try:
            date_input = datetime.fromtimestamp(int(sdi))
            conversion_success = True
        except Exception:
            # conversion failed
            pass

    if not isinstance(date_input, datetime):
        try:
            date_input = dateutil.parser.parse(date_input)
            conversion_success = True
        except Exception:
            pass
    else:
        conversion_success = True

    if not conversion_success:
        date_input = datetime.fromtimestamp(404404404)

    if not date_input.tzinfo:
        date_input = date_input.replace(tzinfo=timezone.utc)

    date_string = datetime.strftime(date_input, "%Y-%m-%dT%H:%M:%S %z")
    # date_string = datetime.strftime(dto, "%Y-%m-%dT%H:%M:%S")
    dto = datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%S %z")
    # dto = datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%S")

    return dto

def dumps(data, indent=4, compactly=False):
    """
    Wrapper for JSON encoding
    """
    if compactly is True or not indent:
        indent = None
    return json.dumps(
        data, indent=indent, cls=JsonComplexEncoder, ensure_ascii=False
    )

def diff_entities(
    # logger: Optional[object] = None,
    dbc: object = None,
    old_entity: Entity = None,
    new_entity: Entity = None,
    add_sensitive: Optional[bool] = True,
):
    """
    Compares two entities.

    :returns: False if they're inherently different (not ents, different label).
        Returns Dict of {'add_has':[], 'remove_has':[], 'equal':True} if they're
        at least the same label.
    """
    _log = dbc.logger
    # if add_sensitive:
    #     _log.debug(f"Comparing entities {old_entity} and {new_entity}")

    if not isinstance(old_entity, (Entity, Relation)):
        _log.error(f"{old_entity} is not an Entity or Relation type!")
        return False
    if not isinstance(new_entity, (Entity, Relation)):
        _log.error(f"{new_entity} is not an Entity or Relation type!")
        return False

    if not hasattr(old_entity, 'label') or not hasattr(new_entity, 'label'):
        _log.error(
            f"Both entities need a label to compare! "
            f"{old_entity} {new_entity}"
        )
        return False

    results = {
        'add_has': [],
        'remove_has': [],
        'add_players': {},
        'remove_players': {},
        'equal': True
    }

    # sensitive attributes should never be removed based on a diff
    sensitive_attrs = [
        'confidence',
        'date-discovered',
        'date-seen',
        'first-seen',
        'last-seen',
        'frequency',
        'note',
        'tag',
        'hunt-active',
        'hunt-endpoint',
        'hunt-string',
        'hunt-service',
        'ref-link',
    ]

    for old_attr in old_entity.has:
        if old_attr.label in sensitive_attrs:
            # _log.debug(f"old_attr {old_attr} is sensitive - skipping comparison!")
            continue
        if old_attr not in new_entity.has:
            # results['equal'] =  False
            if old_attr not in results['remove_has']:
                results['remove_has'].append(old_attr)

    for new_attr in new_entity.has:
        '''
        # removed above because we're un-escaping quotes as they're read in
        # make sure quotes are re-escaped for comparison
        if isinstance(new_attr.value, str):
            # esc_str = re.sub(r"(?<!\\)\"", "\\\"", new_attr.value)

            mod_attr = Attribute(
                iid=new_attr.iid,
                label=new_attr.label,
                value=esc_str
            )
            if mod_attr not in old_entity.has:
                # results['equal'] = False
                if mod_attr not in results['add_has']:
                    results['add_has'].append(mod_attr)
            continue
        '''
        if new_attr not in old_entity.has:
            # results['equal'] = False
            # if a diff result comes with sensitive attributes in add_has,
            # just add them directly to the database, but don't count
            # them in the diff.
            if new_attr.label in sensitive_attrs:
                if add_sensitive:
                    # _log.debug(f"attaching attribute {new_attr} to {old_entity}")
                    # _log.debug(f"...but NOT counting towards diff!")
                    dbc.attach_attribute(old_entity, new_attr)
                '''
                else:
                    _log.debug(
                        f"add_sensitive set to False. Explicitly skipping "
                        f"sensitive attribute for comparison..."
                    )
                    _log.debug(f"...but we would have added {new_attr} to {old_entity}")
                '''
                continue

            if new_attr not in results['add_has']:
                results['add_has'].append(new_attr)

    # This part is probably irrelevant b/c of the new equals logic
    if results['add_has'] or results['remove_has'] or \
        results['add_players'] or results['remove_players']:
        results['equal'] = False
    else:
        results['equal'] = True

    if add_sensitive:
        _log.debug(f"Entity Diff results: {pformat(results)}")
    return results

def diff_relations(
    # logger: Optional[object] = None,
    dbc: object = None,
    old_relation: Relation = None,
    new_relation: Relation = None,
    add_sensitive: Optional[bool] = True,
):
    """
    Compares two Relations.

    :returns: False if they're inherently different (not rels, different label).
        Returns Dict of {
            'equal':True,
            'add_has':[],
            'remove_has':[],
            'add_players': {},
            'remove_players': {},
        }
    """
    _log = dbc.logger
    # _log.debug(f"Comparing relations {old_relation} and {new_relation}")

    if not isinstance(old_relation, Relation):
        _log.error(f"{old_relation} is not an Relation type!")
        return False
    if not isinstance(new_relation, Relation):
        _log.error(f"{new_relation} is not an Relation type!")
        return False

    if not hasattr(old_relation, 'label') or not hasattr(new_relation, 'label'):
        _log.error(
            f"Both entities need a label to compare! "
            f"{old_relation} {new_relation}"
        )
        return False

    results = {
        'add_has': [],
        'remove_has': [],
        'add_players': {},
        'remove_players': {},
        'equal': True
    }

    # Get the attribute/has differential
    has_diff = diff_entities(dbc, old_relation, new_relation, add_sensitive)
    if not has_diff:
        _log.error(f"diffing attributes between relations failed!")
        return False

    # if not has_diff['equal']:
    if not old_relation.has == new_relation.has:
        results['add_has'] = has_diff['add_has']
        results['remove_has'] = has_diff['remove_has']

    # Get the player differential
    for old_role, old_players in old_relation.players.items():
        if old_role not in new_relation.players:
            results['remove_players'][old_role] = old_players
            continue
        for old_player in old_players:
            exists=False
            for new_player in new_relation.players[old_role]:
                if new_player == old_player:
                    exists = True
                    break
                '''
                has_diff = diff_entities(
                    dbc,
                    old_player,
                    new_player,
                    add_sensitive=False
                )
                if has_diff:
                    if has_diff['equal']:
                        exists = True
                        break
                '''
            if not exists:
                if old_role not in results['remove_players']:
                    results['remove_players'][old_role] = []
                results['remove_players'][old_role].append(old_player)


    for new_role, new_players in new_relation.players.items():
        if new_players and new_role not in old_relation.players:
            results['add_players'][new_role] = new_players
            continue
        for new_player in new_players:
            # _log.debug(f"INSPECTING NEW PLAYER {new_player} {new_player.to_dict()}")
            exists = False
            for old_player in old_relation.players[new_role]:
                # _log.debug(f"COMPARING NEW PLAYER TO OLD PLAYER {old_player} {old_player.to_dict()}")
                '''
                has_diff = diff_entities(
                    dbc,
                    old_player,
                    new_player,
                    add_sensitive=False
                )
                if has_diff:
                    if has_diff['equal']:
                        # _log.debug(f"NEW PLAYER {new_player} EXISTS AS OLD PLAYER {old_player}")
                        exists = True
                        # If they're equal, go back and add sensitive attrs
                        diff_entities(
                            dbc,
                            old_player,
                            new_player,
                            add_sensitive=True
                        )
                        break
                '''
                if old_player == new_player:
                    exists = True
                    # make sure we add the sensitive attributes first
                    diff_entities(
                        dbc,
                        old_player,
                        new_player,
                        add_sensitive=True
                    )
                    break
            if not exists:
                if new_role not in results['add_players']:
                    results['add_players'][new_role] = []
                results['add_players'][new_role].append(new_player)

    # Probably irrelevant with new equals logic
    if results['add_has'] or results['remove_has'] or \
        results['add_players'] or results['remove_players']:
        results['equal'] = False
    else:
        results['equal'] = True

    _log.debug(f"Relation Diff Results: {pformat(results)}")
    return results

def flatten_dict(dictionary):
    """
    Flatten a nested JSON file parsed as a dictionary
    """

    def unpack(parent_key, parent_value):
        """Unpack one level of nesting in json file"""
        # Unpack one level only!!!
        # mh.logger.debug(f"Unpacking parent_key: {parent_key} and parent_value: {str(parent_value)[0:35]}")
        if isinstance(parent_value, dict):
            for key, value in parent_value.items():
                temp1 = parent_key + '_' + key
                yield temp1, value
        elif isinstance(parent_value, list):
            i = 0
            if len(parent_value) <= 0:
                # mh.logger.debug(f"parent_value is list of length 0... which is an odd outlier")
                # mh.logger.debug(f"Doing nothing for parent_key: {parent_key}")
                # Do nothing
                pass
            elif isinstance(parent_value[0], dict):
                # mh.logger.debug(f"first item in parent_value list is a dict, so we can't sort it...")
                # Do nothing
                pass
            else:
                try:
                    # mh.logger.debug(f"parent_value is not an empty list and parent_value[0] is not a dict.")
                    # mh.logger.debug(f"...sorting parent_value list...")
                    parent_value.sort()
                except Exception as e:
                    # mh.logger.error(f"FATAL (for now) Error trying to sort {parent_value}")
                    # mh.logger.error(f"{e}")
                    raise
            try:
                for value in parent_value:
                    temp2 = parent_key + '_'+str(i)
                    i += 1
                    yield temp2, value
            except Exception as e :
                raise(e)
        else:

            yield parent_key, parent_value

    # Keep iterating until the termination condition is satisfied
    while True:
        # Keep unpacking the json file until all values are atomic elements (not dictionary or list)
        dictionary = dict(chain.from_iterable(starmap(unpack, dictionary.items())))
        # Terminate condition: not any value in the json file is dictionary or list
        if not any(isinstance(value, dict) for value in dictionary.values()) and \
           not any(isinstance(value, list) for value in dictionary.values()):
            break

    return dictionary

def get_hunt_name(hunt: Relation=None):
    """
    Given a hunt Relation, find its hunt name... I'm tired of typing this out.

    :param hunt: A Relation object with a hunt-name attribute. If no hunt-name
        attribute (which should never happen) we use the Relation IID instead.
    """
    hunt_name = hunt.iid
    for attr in hunt.has:
        if attr.label == 'hunt-name':
            hunt_name = attr.value
    return hunt_name

