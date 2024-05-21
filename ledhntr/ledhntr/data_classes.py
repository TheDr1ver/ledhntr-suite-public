#!/usr/bin/env python3

import copy
import dateutil.parser
import hashlib
import re
import uuid

from abc import ABCMeta
try:
    from collections.abc import MutableMapping
except ImportError:
    from collections import MutableMapping

from datetime import datetime, timezone
from operator import itemgetter
from pkg_resources import resource_stream
from pprint import pprint, pformat
from time import time
from typing import Dict, List, Optional, DefaultDict, Union

import ledhntr.helpers as helpers

def _meta_attrs():
    """
    Meta Attributes are attribute labels that are explicitly ignored when
    making a comparison between two Entity objects. Things like date-seen
    should not be taken into account when determining if two entities are
    equal.
    # ! NOTE - In case you find yourself adding to this list, rest assured
    # ! that this is the only place you need to add to it.
    """
    meta_attrs = [
        'confidence',
        'date-discovered',
        'date-seen',
        'first-hunted',
        'first-seen',
        'frequency',
        'hunt-active',
        # ! https://github.com/TheDr1ver/ledhntr-suite-public/issues/2
        # // 'hunt-name',
        'last-hunted',
        'last-seen',
        'ledid',
        'ledsrc',
        'note',
        'ref-link',
        'tag',
        # ! adding these... really hope this doesn't break stuff
        # ! that I've since forgotten about...
        'hunt-endpoint',
        'hunt-string',
        'hunt-service',
    ]
    return meta_attrs

def _convert_value_types(x, vt):
    """
    List of approved value types.
    I never included integer logic, so I've omitted the 'long' value type
    Keep in mind the RE patterns for value_type_pattern will also need to be
    adjusted if this list changes. This pattern appears both in this file and
    helpers init.
    """
    if x is None:
        return None
    value_types = {
        "boolean": bool,
        # "double": round(float(x),2),
        "string": str,
        "datetime": helpers.format_date,
    }
    if vt=='double':
        return round(float(x), 2)
    else:
        return value_types[vt](x)

def _ledid_explode(objdict: dict = {}):
    """Breaks out sub-objects such that the ledid value can be used as glue

    Breaks out all sub-objects
    into their own representative keys, with nothing but ledid references left
    behind.

    e.g.
        {
            'thingtype': 'relation',
            '_label': 'resolution',
            '_ledid': {
                '_value': 'resolution_1667398442283_29c3e9'
            }
            'players': {
                'query': [
                    {
                        'thingtype': 'entity',
                        '_label': 'domain',
                        '_ledid': {
                            '_value': 'domain_1667398297378_a7bc0b'
                        }
                        'has': [
                            {
                                'thingtype': 'attribute',
                                '_label': 'fqdn',
                                '_value': 'example.com'
                            }
                        ],
                    }
                ]
            }
        }
        ...converts to...
        {
            'relations':[
                {
                    'thingtype': 'relation',
                    '_label': 'resolution',
                    '_ledid': {
                        '_value': 'resolution_1667398442283_29c3e9'
                    }
                    'players': {
                        'query': [
                            {
                                '_ledid': {
                                    '_value': 'domain_1667398297378_a7bc0b'
                                }
                            }
                        ]
                    }
                },
            ],
            'entities': [
                {
                    'thingtype': 'entity',
                    '_label': 'domain',
                    '_ledid': {
                        '_value': 'domain_1667398297378_a7bc0b'
                    }
                    'has': [
                        {
                            'thingtype': 'attribute',
                            '_label': 'fqdn',
                            '_value': 'example.com'
                        }
                    ],
                }
            ],
        }
    :param objdict: Un-exploded dict representation of a Thing Object
    :returns: dict where each object type is in its own key list.
    """
    result = {}

    return result

def _ledid_glue(objdict: dict = {}):
    """Glues an exploded ledid dict back together
    Takes the results from _ledid_explode and combines it back into a single
    dictionary, with all Thing Objects heirarchied where they belong.
    """
    result = {}
    
    return result

def _load_default_schema(schema:str=""):
    """Manually parses schema files and grabs keyvals

    This basically does the exact same thing as helpers.parse_schema_file, but 
    if I want to use it in defining the data classes, I can't have it return the
    data classes themselves.

    :param schema: string location of targeted schema.tql file
    :returns: dict of Thing labels and their associated keyattr thing labels
    """

    if not schema:
        schema = resource_stream('ledhntr', 'schemas/schema.tql').name

    scheyattrs = {}
    schema_val_types = {}

    thing_types = {
        'attribute': ['attribute'],
        'entity': ['entity'],
        'relation': ['relation'],
    }

    pretty_schema = {
        'attribute': [],
        'entity': [],
        'relation': [],
    }

    with open(schema, 'r') as s:
        data = s.read()

    pattern = r"(?s)([a-z0-9\-]+\s+sub.*?);"
    things = re.findall(pattern, data)
    type_parsing = copy.deepcopy(things)

    role_pattern = r"(?s)relates\s+([a-z0-9\-]+)\s*(,|$)"
    attr_pattern = r"(?s)owns\s+([a-z0-9\-]+)\s*(@|,|$)"
    keyattr_pattern = r"(?s)owns\s+([a-z0-9\-]+)\s*@key"
    value_type_pattern = r"(?s)value\s+(boolean|double|string|datetime)\s*"

    re_role = re.compile(role_pattern)
    re_attr = re.compile(attr_pattern)
    re_keyattr = re.compile(keyattr_pattern)
    re_valtype = re.compile(value_type_pattern)

    counter = 1
    while type_parsing and counter < 5:
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
                        info = None
                        if label not in thing_types[key]:
                            thing_types[key].append(label)
                            info = {
                                'label': label,
                                'type': key,
                                'keyattr': None,
                                'owns': [],
                                'value_type': None,
                            }

                        # Get KeyAttr
                        found_keyattr = re_keyattr.search(thing)
                        keyattr = None
                        if found_keyattr:
                            keyattr = found_keyattr[1]

                        if label not in scheyattrs and keyattr:
                            scheyattrs[label]=keyattr
                            if info:
                                info['keyattr']=keyattr

                        # ; Get Owns
                        if info:
                            owns_res = re_attr.findall(thing)
                            for ors in owns_res:
                                if ors[0] not in info['owns']:
                                    info['owns'].append(ors[0])

                        # Get value type for attributes and sub-attributes
                        vt_res = re_valtype.search(thing)
                        if vt_res:
                            value_type = vt_res[1]
                            if label not in schema_val_types:
                                schema_val_types[label]=value_type
                                if info:
                                    info['value_type']=value_type

                        if info:
                            pretty_schema[key].append(info)

                        type_parsing.remove(thing)

        # . _log.debug(f"unparsed types left: {len(type_parsing)}")
        counter += 1
        if counter > 10:
            # ! _log.error(
            # !     f"It should not take more than 10 iterations to processes a schema."
            # !     f" Check your schema layout and try that again..."
            # ! )
            break
    # ! return scheyattrs, schema_val_types, thing_types
    # return pretty_schema
    return scheyattrs, schema_val_types, thing_types, pretty_schema

def _to_dict(obj, classkey=None, ledid_glue:Optional[bool]=False):
    """Function used for all classes to convert them into dicts.
    :param classkey: TBH, IDK how to use this properly. I pulled this code off 
        StackOverflow and it works...
    :param ledid_glue: #TODO# When set to True, instead of returning a regular
        dict representation of the object, it should 
    """
    if isinstance(obj, dict):
        data = {}
        for (k, v) in obj.items():
            data[k] = _to_dict(v, classkey, ledid_glue)
        return data
    elif hasattr(obj, "_ast"):
        return _to_dict(obj._ast())
    elif hasattr(obj, "__dict__"):
        data = dict([(key, _to_dict(value, classkey, ledid_glue))
            for key, value in obj.__dict__.items()
            # if not callable(value) and not key.startswith('_')])
            if not callable(value)])
        if classkey is not None and hasattr(obj, "__class__"):
            data[classkey] = obj.__class__.__name__
        return data
    elif hasattr(obj, "__iter__") and not isinstance(obj, str):
        return [_to_dict(v, classkey) for v in obj]
    else:
        return obj

# default_schema, schema_value_types, thing_types = _load_default_schema()
# pretty_schema = _load_default_schema()
default_schema, schema_value_types, thing_types, pretty_schema = _load_default_schema()


class Thing(MutableMapping, metaclass=ABCMeta):
    def __init__(
        self,
        abstract: Optional[bool] = False,
        iid: Optional[str] = None,
        inferred: Optional[bool] = False,
        label: Optional[str] = None,
        # has: Optional[Union[List[object],List[Dict],Dict,object]] = [],
        # entities: Optional[Union[List[object],List[Dict]]] = [],
        # keyattr: Optional[Union[List[str],str]] = [],
        # owns:  Optional[List[str]] = [],
        # roles: Optional[Union[List[object],List[str]]] = [],
        # players: Optional[Union[Dict[object,List[object]],Dict[str,List[object]], Dict[str,object]]] = {},
        **kwargs
    ) -> None:
        """
        Base-level object used for holding all other Thing Objects.

        :param abstract: Determiens if object label is abstract or
            directly callable
        :param iid: Unique identifier of the Thing
        :param inferred: Set True if Object is ethereal/generated at query time
        :param label: The label for the Thing Object.
        """

        super().__init__()
        # self.__not_jsonable: List[str] = []
        self.abstract = abstract
        self.iid = iid
        self.inferred = inferred
        self._label = label

        '''
        self.has = has or []
        self.entities = entities or []
        self.keyattr = keyattr or []
        self.owns = owns or []
        self.roles = roles or []
        self.players = players or []
        '''

    @property
    def label(self):
        return self._label

    def to_dict(self) -> None:
        res = _to_dict(self)
        return res

    def from_dict(self, **kwargs) -> None:
        for prop, value in kwargs.items():
            if not value:
                continue
            setattr(self, prop, value)
        return self

    def update(self, **kwargs) -> None:
        for prop, value in kwargs.items():
            if not value:
                continue
            setattr(self, prop, value)
        return self

    def __getitem__(self, key):
        try:
            if key[0] != '_':
                return self.__dict__[key]
            raise KeyError
        except AttributeError:
            # Expected by pop and other dict-related methods
            raise KeyError

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __delitem__(self, key):
        delattr(self, key)

    def __iter__(self):
        '''When we call **self, skip keys:
            * starting with _
            * in __not_jsonable
            * timestamp if the object is edited *unless* it is forced
        '''
        return iter(
            {k: v for k, v in self.__dict__.items()
            if not (k[0] == '_'
                    # or k in self.__not_jsonable
                    )}
        )
    def __len__(self) -> int:
        return len(
            [k for k in self.__dict__.keys()
            if not (k[0] == '_'
                # or k in self.__not_jsonable
                )]
        )

    def __repr__(self) -> str:
        if self.label:
            s = f"<{self.__class__.__name__}(label={self.label})"
            if self.iid:
                s = f"<{self.__class__.__name__}(label={self.label},iid={self.iid})"
        else:
            s = f"<{self.__class__.__name__}(NotInitialized)"
        return s

def _keyval(
    thing: Thing = None,
):
    """Return value of associated keyattr
    This function rolls through a given Entity or Relation's attribtues to find
    the value of its key attribute
    """
    if not hasattr(thing, 'keyattr') or not thing.keyattr:
        return None
    if hasattr(thing, 'has') and thing.has:
        for attr in thing.has:
            if attr.label == thing.keyattr:
                return attr.value
        return None
    return None

class Attribute(Thing):
    def __init__(
        self,
        value: Union[str,datetime,float] = None,
        value_type: str = "",
        **kwargs
    ) -> None:
        """
        Object used for holding Attribute Things from the database.

        :param value: Raw value for the attribute.
        """

        super().__init__(**kwargs)
        self.thingtype = 'attribute'
        if self._label == "date-seen" \
        or self._label == "date-discovered" \
        or self._label == "first-seen" \
        or self._label == "last-seen":
            if not isinstance(value, datetime):
                try:
                    _value = dateutil.parser.parse(value)
                    if not _value.tzinfo:
                        _value = _value.replace(tzinfo=timezone.utc)
                    self._value = _value
                except Exception:
                    self._value = None
            else:
                self._value = value
        else:
            self._value = value

        if not value_type and self._label in schema_value_types:
            self._value_type=schema_value_types[self._label]
        else:
            self._value_type = value_type

        if self._value_type:
            try:
                self._value = _convert_value_types(self._value, self._value_type)
            except Exception as e:
                print(f"label={self.label} value={self.value} vt={self._value_type}")
                raise e

    @property
    def value(self):
        return self._value

    @property
    def value_type(self):
        return self._value_type

    def to_dict(self, ledid_glue: Optional[bool]=False):
        """Convert Relation object to dictionary
        :param ledid_glue: If set to True, returns each object under separate keys
            depending on what type it is. The only thing remaining where it used
            to be is the ledid value so it can be stitched back together after
            the fact.

            You would want to use this if you're storing each relation,
            entity, and attribute as a separate JSON file so you don't end up with
            attr1=example.com with multiple ledid's across multiple entities and
            relations.

        :returns: Dict representation of object
        """
        # obj = {"Attribute": self.__dict__}
        res = _to_dict(self, ledid_glue=ledid_glue)
        return res

    def to_json(self, indent=4, compactly=False):
        data = self.__dict__
        return helpers.dumps(data, indent=indent, compactly=compactly)

    def from_dict(self, **kwargs):
        if "Attribute" in kwargs:
            kwargs = kwargs['Attribute']
        res = super(Attribute, self).from_dict(**kwargs)
        return res

    def __eq__(self, other):
        return isinstance(other, Attribute) and self.label == other.label and self.value == other.value

    def __hash__(self):
        return hash((self._label,self._value))

    def __repr__(self) -> str:
        if self._label:
            s = f"<{self.__class__.__name__}(label={self.label})"
            if self._value:
                s = f"<{self.__class__.__name__}(label={self.label},value={self.value})"
        else:
            s = f"<{self.__class__.__name__}(NotInitialized)"
        return s

def _comboid_calc(obj):
    """calculate hash value based on non-meta attached attributes
    The hash value resulting from _comboid_calc() is a sha256 hash resulting
    from the non-meta attached attributes for an entity or relation.

    Generally speaking, this would only be used for entity or relation types
    that don't have a natural value to key off of (think geoloc or whois records)
    
    :param obj: any Thing object
    :returns: Attribute of 'comboid' type with sha256 string value or None if
        invalid object was fed
    """
    sha256 = None

    if not hasattr(obj, 'has'):
        # // return sha256
        return Attribute(label='comboid', value="")
    if not hasattr(obj, 'meta_attrs'):
        # // return sha256
        return Attribute(label='comboid', value="")
    
    comboid_attrs = {}
    for attr in obj.has:
        if attr.label in obj.meta_attrs:
            continue
        if attr.label not in comboid_attrs:
            comboid_attrs[attr.label]=[attr.value]
            continue
        comboid_attrs[attr.label].append(attr.value)

    if not comboid_attrs:
        # ! If the only thing you have is Meta Attributes then you'll get an
        # ! empty hash. Therefore you should instead return None because you
        # ! have an invalid object.
        return Attribute(label='comboid', value="")
    # Sort lists of values
    list_sorted = {}
    for k, v in comboid_attrs.items():
        v.sort()
        list_sorted[k]=v
    # Sort Dict based on keys
    comboid = dict(sorted(list_sorted.items(), key=itemgetter(0,1)))

    comboid_string=""
    for label, values in comboid.items():
        for value in values:
            if comboid_string:
                comboid_string += ";;"
            comboid_string += f"{label}::{value}"

    sha256 = hashlib.sha256(comboid_string.encode('utf-8')).hexdigest()
    final_comboid =  Attribute(label='comboid', value=sha256)
    return final_comboid

def _gen_ledid(
    label: Union[str, Thing] = None,
):
    """
    In order to do things like proper pagination, a unique attribute is required
    for Entities and Relations, since at this time sorting cannot be conducted
    based on the internal `iid` value inherent to all TypeDB objects.

    This function generates a unique identifier based on the label, time of
    generation, and a truncated uuid to avoid any potential collisions.
    """
    if isinstance(label, Thing):
        label = label._label
    val = f"{label}_{int(time()*1000)}_{uuid.uuid4().hex[0:6]}"
    ledid = Attribute(label='ledid', value=val)
    return ledid

class Entity(Thing):
    def __init__(
        self,
        has: Optional[Union[List[Attribute],List[Dict],Dict,List]] = [],
        keyattr: Optional[str] = '',
        owns:  Optional[List[str]] = [],
        relations: Optional[Union[List[object],List[Dict]]] = [],
        plays: Optional[List[Dict]] = [],
        **kwargs
    ) -> None:
        """
        Object used for holding Relationship Things from the database.

        :param has: Attributes belonging to the Relationship
        :param keyattr: If @key attribtues exist for this relationship in the
            schema, store them here as string values
        :param owns: List of potential attributes that can be assigned to
            this Relation
        :param relations: List of Relations this Entity can be added to
        :param plays: List of {Role:Relation} dictionaries describing which
            Relations this Entity currently belongs to.
        """

        super().__init__(**kwargs)
        self.thingtype = 'entity'
        # super()__init__(**kwargs)
        self.has = has or []
        if not isinstance(self.has, list):
            self.has = [self.has]

        new_has = []

        # Generate ledid automatically
        if self._label:
            self._ledid = None
            for h in self.has:
                if isinstance(h,Attribute) and h.label=='ledid':
                    self._ledid = h
            if not self._ledid:
                self._ledid = _gen_ledid(self._label)
                self.has.append(self._ledid)

        # self.keyattr = keyattr
        if keyattr:
            self.keyattr = keyattr
        else:
            self.keyattr = self._get_keyattr()
        self.owns = owns or []
        self.relations = relations or []
        self.plays = plays or []

    def _get_keyattr(self):
        keyattr = ''
        if self.label in default_schema:
            keyattr = default_schema[self.label]
        return keyattr

    def _sort_attributes(self, attributes: List = [],):
        res_tups = []
        meta_attrs = self.meta_attrs
        while None in attributes:
            attributes.remove(None)
        for attr in attributes:
            # If a keyattribute is set, the only tuple we need is the one for
            # that specific attribute
            if self.keyattr:
                if attr.label != self.keyattr:
                    continue
                if attr.label == self.keyattr:
                    attr_tup = (attr.label,attr.value)
                    res_tups.append(attr_tup)
                    return sorted(res_tups)

            if attr.label in meta_attrs:
                continue

            attr_tup = (attr.label,attr.value)
            res_tups.append(attr_tup)
        return sorted(res_tups)

    def get_attributes(
        self,
        label: str="",
        first_only: Optional[bool] = False,
    ):
        """Get attribute from entity matching label
        :param label: Attribute label to match on
        :param first_only: Flag to return only the first matching attribute

        :returns: List of Attribute objects matching label (or [] if no match).
            If first_only=True, returns first matching Attribute or None if no match.
        """
        attrs = []
        if hasattr(self, 'has') and self.has:
            for attr in self.has:
                if attr is None:
                    continue
                if attr.label==label:
                    if first_only:
                        return attr
                    attrs.append(attr)
        if first_only:
            return None
        return attrs

    @property
    def keyval(self):
        return _keyval(thing=self)

    @property
    def ledid(self):
        if self._ledid:
            return self._ledid.value
        else:
            return None

    @ledid.setter
    def ledid(
        self,
        value: Union[str, Attribute] = None,
    ):
        if isinstance(value, str) and value:
            value = Attribute(label='ledid', value=value)
        if not isinstance(value, Attribute):
            self._ledid = None
        elif not value.label=='ledid':
            self._ledid = None
        else:
            self._ledid = value
        # Make sure the only ledid attribute in self.has is the right one.
        safe_loop = copy.deepcopy(self.has)
        for attr in safe_loop:
            if attr.label=='ledid':
                self.has.remove(attr)
        if self._ledid:
            self.has.append(self._ledid)

    @ledid.deleter
    def ledid(self):
        self._ledid = None
        safe_loop = copy.deepcopy(self.has)
        for attr in safe_loop:
            if attr.label=='ledid':
                self.has.remove(attr)

    @property
    def meta_attrs(self):
        return _meta_attrs()

    def get_comboid(self):
        """Generate a 'comboid' Attribute based on this object's existing attrs
        """
        return _comboid_calc(self)

    def merge(self, **kwargs):
        safe_copy_self_has = []
        safe_copy_new_has = []

        for k, v in kwargs.items():
            if isinstance(v, list):
                if k == 'has':
                    safe_copy_self_has = copy.deepcopy(self.has)
                    safe_copy_new_has = copy.deepcopy(v)

        for attr in safe_copy_new_has:
            if attr not in safe_copy_self_has:
                # We don't want duplicates of any of these attribute types
                if attr.label == "first-seen":
                    continue
                if attr.label == "last-seen":
                    continue
                if attr.label == 'ledid':
                    continue
                if attr.label == 'confidence':
                    continue
                if attr.label == 'date-discovered':
                    continue
                self.has.append(attr)
        return self

    def to_dict(self, ledid_glue: Optional[bool]=False):
        """Convert Relation object to dictionary
        :param ledid_glue: If set to True, returns each object under separate keys
            depending on what type it is. The only thing remaining where it used
            to be is the ledid value so it can be stitched back together after
            the fact.

            You would want to use this if you're storing each relation,
            entity, and attribute as a separate JSON file so you don't end up with
            attr1=example.com with multiple ledid's across multiple entities and
            relations.

        :returns: Dict representation of object
        """
        # obj = {"Entity": self.__dict__}
        res = _to_dict(self, ledid_glue=ledid_glue)
        return res

    def from_dict(self, **kwargs):
        if "Entity" in kwargs:
            kwargs = kwargs['Entity']
        if '_ledid' in kwargs and kwargs['_ledid']:
            ledid_dict = kwargs['_ledid']
            if isinstance(ledid_dict,dict) and 'thingtype' in ledid_dict and ledid_dict['thingtype']=='attribute':
                attr_obj = Attribute()
                new_attr = attr_obj.from_dict(**ledid_dict)
                kwargs['_ledid'] = new_attr
        if 'has' in kwargs and kwargs['has']:
            conv_has = []
            for attr in kwargs['has']:
                if isinstance(attr, dict) and 'thingtype' in attr and attr['thingtype']=='attribute':
                    attr_obj = Attribute()
                    new_attr = attr_obj.from_dict(**attr)
                    conv_has.append(new_attr)
            kwargs['has'] = conv_has
        res = super(Entity, self).from_dict(**kwargs)
        return res

    def to_json(self, indent=4, compactly=False):
        data = self.__dict__
        return helpers.dumps(data, indent=indent, compactly=compactly)

    def __eq__(self, other):
        if not isinstance(other, Entity):
            return False

        self_attrs = self._sort_attributes(self.has)
        other_attrs = self._sort_attributes(other.has)
        self_group = [self.label] + self_attrs
        other_group = [other.label] + other_attrs
        return self_group == other_group

    def __repr__(self) -> str:
        iid = None
        con = None
        keyattr = None
        has = None
        inferred = None
        if self._label:
            s = f"<{self.__class__.__name__}(label={self.label}"
            if self.iid:
                # s += f",iid={self.iid}"
                iid = f",iid={self.iid}"
            if self.has:
                if self.keyattr:
                    ka = self.keyattr
                else:
                    ka = None
                for h in self.has:
                    if not h:
                        continue
                    if h.label == 'confidence':
                        # s += f",con={h.value}"
                        con = f",con={h.value}"
                    if ka is not None and h.label == ka:
                        # s += f",{ka}={h.value}"
                        keyattr = f",{ka}={h.value}"
                # s += f",has={len(self.has)}"
                has = f",has={len(self.has)}"
            if self.inferred:
                # s += f",inferred=True"
                inferred = f",inferred=True"

            # Build string
            if con:
                s += con
            if iid:
                s += iid
            if keyattr:
                s += keyattr
            if has:
                s += has
            if inferred:
                s += inferred

            s += ")"
        else:
            s = f"<{self.__class__.__name__}(NotInitialized)"
        return s

class Role(Thing):
    def __init__(
        self,
        scope: Optional[str] = None,
        scoped_name: Optional[str] = None,
        **kwargs
    ) -> None:
        """
        Defines Role object, generally as it's assigned to an Relation

        This class is stupid and totally pointless FWIW.

        :param scope: Scope of the role
        :param scope_name: Scope:Name of the role
        """

        super().__init__(**kwargs)
        self.thingtype = 'role'
        self.scope = scope
        self.scoped_name = scoped_name

    def to_dict(self):
        res = {"Role": self.__dict__}
        return res

    def to_json(self, indent=4, compactly=False):
        data = self.__dict__
        return helpers.dumps(data, indent=indent, compactly=compactly)

    def from_dict(self, **kwargs):
        if "Role" in kwargs:
            kwargs = kwargs['Role']
        super(Role, self).from_dict(**kwargs)

    def __repr__(self) -> str:
        if self._label:
            s = f"<{self.__class__.__name__}(label={self._label})"
            if self.scoped_name:
                s += f",scoped_name={self.scoped_name})"
        else:
            s = f"<{self.__class__.__name__}(NotInitialized)"
        return s

class Relation(Thing):
    def __init__(
        self,
        has: Optional[Union[List[Attribute],List[Dict],Dict,Attribute]] = [],
        entities: Optional[Union[List[Entity],List[Dict]]] = [],
        keyattr: Optional[str] = '',
        owns:  Optional[List[str]] = [],
        relations: Optional[Union[List[object],List[Dict]]] = [],
        roles: Optional[Union[List[Role],List[str]]] = [],
        players: Optional[Union[Dict[Role,List[Entity]],Dict[str,List[Entity]], Dict[str,Entity]]] = {},
        **kwargs
    ) -> None:
        """
        Object used for holding Relationship Things from the database.

        :param has: Attributes belonging to the Relationship
        :param entities: Entities belonging to the Relationship
            (probably redundant from players)
        :param keyattr: If @key attributes exist for this relationship in the
            schema, store them here as string values
        :param owns: List of potential attributes that can be assigned to
            this Relation
        :param roles: List of Roles that can be assigned to this Relation
        :param players: Existing entities assigned a specific role.
            (e.g. {
                'resolved-from': Entity(
                    label="hostname",
                    has=[
                        Attribute(
                            label="fqdn",
                            value="test.example.com"
                        )
                    ]
                )
            })
        """

        super().__init__(**kwargs)
        self.thingtype = 'relation'
        self.has = has or []
        if not isinstance(self.has, list):
            self.has = [self.has]

        # Generate ledid automatically
        if self._label:
            self._ledid = None
            for h in self.has:
                if isinstance(h,Attribute) and h.label=='ledid':
                    self._ledid = h
            if not self._ledid:
                self._ledid = _gen_ledid(self._label)
                self.has.append(self._ledid)

        self.entities = entities or {}
        # self.keyattr = keyattr
        if keyattr:
            self.keyattr = keyattr
        else:
            self.keyattr = self._get_keyattr()
        self.owns = owns or []
        self.relations = relations or []
        self.roles = roles or []
        self.players = players or {}
        for k, v in self.players.items():
            if not isinstance(v, list):
                self.players[k]=[v]

    def _get_keyattr(self):
        keyattr = ''
        if self.label in default_schema:
            keyattr = default_schema[self.label]
        return keyattr

    def _sort_attributes(self, attributes: List = [],):
        res_tups = []
        meta_attrs = self.meta_attrs
        while None in attributes:
            attributes.remove(None)
        for attr in attributes:
            # If a keyattribute is set, the only tuple we need is the one for
            # that specific attribute
            if self.keyattr:
                if attr.label != self.keyattr:
                    continue
                if attr.label == self.keyattr:
                    attr_tup = (attr.label,attr.value)
                    res_tups.append(attr_tup)
                    return sorted(res_tups)

            if attr.label in meta_attrs:
                continue
            attr_tup = (attr.label,attr.value)
            res_tups.append(attr_tup)
        return sorted(res_tups)

    def _sort_players(self, role_players: Dict = {},):
        res_tups = []
        for role, players in role_players.items():
            player_tups = []
            for player in players:
                sorted_attrs = player._sort_attributes(player.has)
                player_tup = (player.label, sorted_attrs)
                player_tups.append(player_tup)
            res_tups.append((role, sorted(player_tups)))
        return sorted(res_tups)

    def get_attributes(
        self,
        label: str="",
        first_only: Optional[bool] = False,
    ):
        """Get attribute from entity matching label
        :param label: Attribute label to match on
        :param first_only: Flag to return only the first matching attribute

        :returns: List of Attribute objects matching label (or [] if no match).
            If first_only=True, returns first matching Attribute or None if no match.
        """
        attrs = []
        if hasattr(self, 'has') and self.has:
            for attr in self.has:
                if attr is None:
                    continue
                if attr.label==label:
                    if first_only:
                        return attr
                    attrs.append(attr)
        if first_only:
            return None
        return attrs

    @property
    def keyval(self):
        return _keyval(thing=self)

    @property
    def ledid(self):
        if self._ledid:
            return self._ledid.value
        else:
            return None

    @ledid.setter
    def ledid(
        self,
        value: Union[str, Attribute] = None,
    ):
        if isinstance(value, str) and value:
            value = Attribute(label='ledid', value=value)
        if not isinstance(value, Attribute):
            self._ledid = None
        elif not value.label=='ledid':
            self._ledid = None
        else:
            self._ledid = value
        # Make sure the only ledid attribute in self.has is the right one.
        safe_loop = copy.deepcopy(self.has)
        for attr in safe_loop:
            if attr.label=='ledid':
                self.has.remove(attr)
        if self._ledid:
            self.has.append(self._ledid)

    @ledid.deleter
    def ledid(self):
        self._ledid = None
        safe_loop = copy.deepcopy(self.has)
        for attr in safe_loop:
            if attr.label=='ledid':
                self.has.remove(attr)

    @property
    def meta_attrs(self):
        return _meta_attrs()

    @property
    def eq_ignore_players(self):
        """
        Returns a list of Relationships where the players should be ignored when
        determining if they are equal or not. For example, a geoloc relation should
        be considered unique/equal to another Relation strictly based on the
        Attributes attached to it, rather than the Entities it contains as players.

        However, something like 'network-service' should be duplicated normally
        because their players are what make them unique.
        """

        ignore_players = [
            'actor-cluster',
            'autonomous-system',
            'cidr',
            'enrichment',
            'geoloc',
            'hunt',
            # network-service needs to take players into account.
            # a network-service that finds nginx software ent and an HTTP ent
            # is not the same as a network-service that finds a DNS service.
            # 'network-service',
        ]

        return ignore_players

    def get_comboid(self):
        """Generate a 'comboid' Attribute based on this object's existing attrs
        """
        return _comboid_calc(self)

    def __eq__(self, other):

        if not isinstance(other, Relation):
            return False

        self_attrs = self._sort_attributes(self.has)
        other_attrs = self._sort_attributes(other.has)

        # If this relation has a key assigned to it, that's all we need to know
        if self.keyattr:
            self_group = [self.label] + self_attrs
            other_group = [other.label] + other_attrs
            return self_group == other_group

        eq_ignore_players = self.eq_ignore_players
        # if this is a label where we should ignore the attached players, just
        # compare the label and associated attributes.
        if self.label in eq_ignore_players:
            self_group = [self.label] + self_attrs
            other_group = [other.label] + other_attrs
            return self_group == other_group

        self_players = self._sort_players(self.players)
        other_players = self._sort_players(other.players)

        self_group = [self.label] + self_attrs + self_players
        other_group = [other.label] + other_attrs + other_players

        return self_group == other_group


    def to_dict(self, ledid_glue: Optional[bool]=False):
        """Convert Relation object to dictionary
        :param ledid_glue: If set to True, returns each object under separate keys
            depending on what type it is. The only thing remaining where it used
            to be is the ledid value so it can be stitched back together after
            the fact.

            You would want to use this if you're storing each relation,
            entity, and attribute as a separate JSON file so you don't end up with
            attr1=example.com with multiple ledid's across multiple entities and
            relations.

        :returns: Dict representation of object
        """
        # obj = {"Relation": self.__dict__}
        res = _to_dict(self, ledid_glue=ledid_glue)
        return res

    def from_dict(self, **kwargs):
        if "Relation" in kwargs:
            kwargs = kwargs['Relation']
        if '_ledid' in kwargs and kwargs['_ledid']:
            ledid_dict = kwargs['_ledid']
            if isinstance(ledid_dict,dict) and 'thingtype' in ledid_dict and ledid_dict['thingtype']=='attribute':
                attr_obj = Attribute()
                new_attr = attr_obj.from_dict(**ledid_dict)
                kwargs['_ledid'] = new_attr
        if 'has' in kwargs and kwargs['has']:
            conv_has = []
            for attr in kwargs['has']:
                if isinstance(attr, dict) and 'thingtype' in attr and attr['thingtype']=='attribute':
                    attr_obj = Attribute()
                    new_attr = attr_obj.from_dict(**attr)
                    conv_has.append(new_attr)
            kwargs['has'] = conv_has
        if 'players' in kwargs and kwargs['players']:
            for role, players in kwargs['players'].items():
                conv_ents = []
                for player in players:
                    if isinstance(player, dict) and 'thingtype' in player and player['thingtype']=='entity':
                        ent_obj = Entity()
                        new_ent = ent_obj.from_dict(**player)
                        conv_ents.append(new_ent)
                kwargs['players'][role] = conv_ents
        res = super(Relation, self).from_dict(**kwargs)
        return res

    def to_json(self, indent=4, compactly=False):
        data = self.__dict__
        return helpers.dumps(data, indent=indent, compactly=compactly)

    def merge(self, **kwargs):
        """
        A merge takes a new Thing object as **kwargs and adds any entities or
        players the existing one may not have had. It does NOT remove any
        entities from the pre-existing object.
        """
        safe_copy_self_has = []
        safe_copy_new_has = []
        safe_copy_self_players = {}
        safe_copy_new_players = {}

        for k, v in kwargs.items():

            if k == 'has':
                safe_copy_self_has = copy.deepcopy(self.has)
                safe_copy_new_has = copy.deepcopy(v)

            if k == 'players':
                safe_copy_self_players = copy.deepcopy(self.players)
                safe_copy_new_players = copy.deepcopy(v)

        for obj in safe_copy_new_has:
            if obj not in safe_copy_self_has:
                # We don't want duplicates of any of these attribute types
                if obj.label == "first-seen":
                    continue
                if obj.label == "last-seen":
                    continue
                if obj.label == 'ledid':
                    continue
                if obj.label == 'confidence':
                    continue
                if obj.label == 'date-discovered':
                    continue
                self.has.append(obj)

        # Strip iid's
        for role, players in self.players.items():
            pi = 0
            for player in players:
                # TODO - maybe put back in the iid scrub?
                # player.iid = ""
                # safe_copy_self_players[role][pi].iid = ""
                safe_copy_self_players[role][pi].relations = []
                safe_copy_self_players[role][pi].plays = []
                safe_copy_self_players[role][pi].owns = []
                '''
                hi = 0
                if player.has:
                    for attr in player.has:
                        safe_copy_self_players[role][pi].has[hi].iid = ""
                        hi += 1
                '''
                pi+=1
                '''
                if player.has:
                    hi = 0
                    for attr in player.has:
                        safe_copy_self_players[role][pi]
                        attr.iid = ""
                '''
        safe_copy_new_players_2 = copy.deepcopy(safe_copy_new_players)
        # for role, players in safe_copy_new_players.items():
        for role, players in safe_copy_new_players_2.items():
            pi = 0
            for player in players:
                # player.iid = ""
                # safe_copy_new_players[role][pi].iid = ""
                safe_copy_new_players[role][pi].relations = []
                safe_copy_new_players[role][pi].plays = []
                safe_copy_new_players[role][pi].owns = []
                '''
                hi = 0
                if player.has:
                    for attr in player.has:
                        # attr.iid = ""
                        safe_copy_new_players[role][pi].has[hi].iid = ""
                        hi += 1
                '''
                pi += 1

        # add players
        for role, players in safe_copy_new_players.items():
            if role not in safe_copy_self_players:
                safe_copy_self_players[role] = []
                self.players[role] = []
            for player in players:
                if player not in safe_copy_self_players[role]:
                    self.players[role].append(player)

        return self

    def __repr__(self) -> str:
        iid = None
        con = None
        keyattr = None
        has = None
        roles = None
        plays = None
        inferred = None
        if self._label:
            s = f"<{self.__class__.__name__}(label={self.label}"
            if self.iid:
                # s += f",iid={self.iid}"
                iid = f",iid={self.iid}"
            if self.has:
                if self.keyattr:
                    ka = self.keyattr
                else:
                    ka = None
                for h in self.has:
                    if not h:
                        continue
                    if h.label == 'confidence':
                        # s += f",con={h.value}"
                        con = f",con={h.value}"
                    if ka is not None and h.label == ka:
                        # s += f",{ka}={h.value}"
                        keyattr = f",{ka}={h.value}"
                # s += f",has={len(self.has)}"
                has = f",has={len(self.has)}"
            if self.players:
                roles = f",active_roles={len(self.players)}"
                total_players = 0
                for role, players in self.players.items():
                    if players:
                        for player in players:
                            total_players += 1
                plays = f",total_players={total_players}"
            if self.inferred:
                # s += f",inferred=True"
                inferred = f",inferred=True"

            # Build string
            if con:
                s += con
            if iid:
                s += iid
            if keyattr:
                s += keyattr
            if has:
                s += has
            if roles:
                s += roles
            if plays:
                s += plays
            if inferred:
                s += inferred
            s += ")"

        else:
            s = f"<{self.__class__.__name__}(NotInitialized)(all={self.to_dict()})"
        return s

class Query():
    def __init__(
        self,
        qtype: str = "match",
        string: Optional[str] = None,
        answers: Optional[List[object]] = [],
        target_thing: Optional[object] = None,
        search_mode: Optional[str] = "full",
        **kwargs
    ) -> None:
        """
        Query object used for feeding queries with proper syntax to the database.

        :param qtype: Method used for querying the database. Defaults to Match.
        :param string: Raw query sent to the database
        :param answers: Placeholder used for retaining responses from the query
        :param target_thing: The target thing used to build this query in the first
            place. Primarily used to ensure database write responses match the
            object type used to build the query.
        :param search_mode: "full", "lite", or "no_backtrace".
            - "full" (Default) pulls down all details of all subset Things. (e.g. if you get
            a Relation with 3 Entities, it will populate ALL attributes associated
            with each entity).
            - "lite" only returns the top-level object discovered in the current
            concept with its immediate Attributes, but does not attempt to enrich
            any next-level Entities or Relations
            - "no_backtrace" is only for Relation things. It gets all attributes
                of the given Relation, all roles & sub-entities, but no attributes
                of those entities, nor does it cause the entities to find all
                Relations associated with each entity
        """
        self.qtype = qtype
        self.string = string
        self.answers = answers
        self.target_thing = target_thing
        self.search_mode = search_mode

    def pp(self) -> str:
        simple_queries = ["match", "insert"]
        string = ""
        if self.qtype in simple_queries:
            string += self.qtype+"\n    "
        syntax = self.string.replace(";", ";\n    ")
        syntax = syntax.replace(",", ",\n        ")
        string += syntax
        return string

    def to_dict(self):
        res = {"Query": self.__dict__}
        return res

    def __repr__(self) -> str:
        if self.string:
            s = f"<{self.__class__.__name__}(length={len(self.string)}"
            if self.answers:
                s += f",answers={len(self.answers)}"
            if self.target_thing:
                s += f",target_thing={self.target_thing}"
            s += ")"
        else:
            s = f"<{self.__class__.__name__}(NotInitialized)"
        return s

def build_schema():
    """Builds a dictionary of all potential things from the default schema
    :returns: dict of all schema metadata
    """
    # default_schema, schema_value_types, thing_types = _load_default_schema()
    schema = {'attribute':[], 'entity':[], 'relation':[]}
    for ttype, labels in thing_types.items():
        for label in labels:
            info = {
                'label': label,
                'type': ttype,
                'keyattr': None,
                'value_type': None,
            }
            if label in default_schema:
                info['keyattr'] = default_schema[label]
            if label in schema_value_types:
                info['value_type'] = schema_value_types[label]
            schema[ttype].append(info)
    return schema