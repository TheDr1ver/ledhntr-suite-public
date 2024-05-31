"""
Overview
========

This is a connector plugin explicitly used for interacting with a
TypeDB database.


# @ DEV NOTE - deving this in the tdbdriver conda environment - Python 3.11.5
# @ using typedb-driver 2.28.0 and local/docker-hosted typedb server 2.28.0
"""

import copy
import dateutil.parser
import logging
import re

from datetime import datetime, timezone
from pkg_resources import resource_stream
from pprint import pformat
from typedb.driver import (
    Annotation,
    TypeDB,
    TypeDBOptions,
    SessionType,
    TransactionType,
    Iterator,
    ConceptMap,
    TypeDBCredential,
    TypeDBException,
    TypeDBDriverException,
    TypeDBDriverExceptionNative,
    # QueryFuture, # Not sure what this maps to yet
    
)

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
from ledhntr.helpers import format_date, diff_entities, diff_relations
from ledhntr.plugins.connector import ConnectorPlugin

class TypeDBClient(ConnectorPlugin):
    """
    TypeDBClient

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
        self.cloud_user = config.get(
            'options',
            'user',
            fallback = 'admin',
        )

        self.cloud_pass = config.get(
            'options',
            'password',
            fallback = 'password',
        )

        self.cloud_tls = bool(config.get(
            'options',
            'tls',
            fallback = True,
        ))

        self.db_server = config.get(
            'options',
            'db_server',
            fallback = 'https://localhost:1729',
        )

        self.db_name = config.get(
            'options',
            'db_name',
            fallback = 'dev_db',
        )

        self.parallelisation = int(config.get(
            'options',
            'parallelisation',
            fallback = 2
        ))

        infer = bool(config.get(
            'db_options',
            'infer',
            fallback = False,
        ))

        explain = bool(config.get(
            'db_options',
            'explain',
            fallback = False,
        ))

        parallel = bool(config.get(
            'db_options',
            'parallel',
            fallback = True,
        ))

        prefetch_size = int(config.get(
            'db_options',
            'prefetch_size',
            fallback = 50,
        ))

        trace_inference = bool(config.get(
            'db_options',
            'trace_inference',
            fallback = False
        ))

        session_idle_timeout_millis = int(config.get(
            'db_options',
            'session_idle_timeout_millis',
            fallback = 30000,
        ))

        transaction_timeout_millis = int(config.get(
            'db_options',
            'transaction_timeout_millis',
            fallback = 300000,
        ))

        schema_lock_acquire_timeout_millis = int(config.get(
            'db_options',
            'schema_lock_acquire_timeout_millis',
            fallback = 10000,
        ))


        self.db_options = self._set_db_options(
            infer=infer,
            explain=explain,
            parallel=parallel,
            prefetch_size=prefetch_size,
            trace_inference=trace_inference,
            session_idle_timeout_millis=session_idle_timeout_millis,
            transaction_timeout_millis=transaction_timeout_millis,
            schema_lock_acquire_timeout_millis=schema_lock_acquire_timeout_millis,
        )

        self.client = None
        self.session = None
        self.tx = None
        self.tx_timer = int(datetime.now().timestamp())
        self.session_timer = int(datetime.now().timestamp())
        self.generic_client_counter = 0
        self.client = self.create_client()
        self.schema = {} # populate with load_schema()
        self.thing_keys = {} # populate with get_thing_keys()
        # adding debug flag for doing things like making sure we always print
        # the resulting iid of a newly-added Thing
        self.debug = False

    def _get_tx_action_from_qtype(
        self,
        qtype: str = '',
        tx: object = None,
    ):
        """
        Given a Query.qtype string, find the appropriate transaction action

        :param qtype: query type (e.g. 'insert' or 'match_group_aggregate')
        :param tx: active transaction
        """

        _log = self.logger
        # ! 
        '''
        map = {
            "match": tx.query.match,
            "match_delete": tx.query.delete,
            "match_insert": tx.query.insert,
            "match_aggregate": tx.query.match_aggregate,
            "match_group": tx.query.match_group,
            "match_group_aggregate": tx.query.match_group_aggregate,
            "insert": tx.query.insert,
            "delete": tx.query.delete,
            "update": tx.query.update,
            "explain": tx.query.explain,
            "define": tx.query.define,
            "undefine": tx.query.undefine,
        }
        '''
        map = {
            "match": tx.query.get,
            "match_delete": tx.query.delete,
            "match_insert": tx.query.insert,
            "match_aggregate": tx.query.get_aggregate,
            "match_group": tx.query.get_group,
            "match_group_aggregate": tx.query.get_group_aggregate,
            "insert": tx.query.insert,
            "delete": tx.query.delete,
            "update": tx.query.update,
            "explain": tx.query.explain,
            "define": tx.query.define,
            "undefine": tx.query.undefine,
        }
        if qtype not in map:
            _log.error(f"qtype {qtype} is not a valid query action!")
            raise
        tx_action = map[qtype]
        return tx_action

    def _set_confidence(
        self,
        things: List[Thing] = []
    ):
        """Sets 'unknown' confidence by default to all Entities and Relations

        :param things: List of Things to add confidence to
        :returns: List of Things
        """
        _log = self.logger
        _log.debug(f"Adding unknown confidence to all Entities and Relations...")
        default_confidence = Attribute(label='confidence', value=0.0)
        con_counter = 0
        for thing in things:
            if isinstance(thing, (Entity, Relation)):
                if not thing.get_attributes('confidence'):
                    thing.has.append(default_confidence)
                    con_counter += 1
        _log.debug(f"Added {con_counter} confidence attributes!")
        return things

    def _set_db_options(
        self,
        infer: Optional[bool] = False,
        explain: Optional[bool] = False,
        parallel: Optional[bool] = True,
        prefetch_size: Optional[int] = 50,
        trace_inference: Optional[bool] = False,
        session_idle_timeout_millis: Optional[int] = 30000,
        transaction_timeout_millis: Optional[int] = 300000,
        schema_lock_acquire_timeout_millis: Optional[int] = 10000,
    ):
        options = TypeDBOptions()
        options.infer = infer
        options.explain = explain
        options.parallel = parallel
        options.prefetch_size = prefetch_size
        options.trace_inference = trace_inference
        options.session_idle_timeout_millis = session_idle_timeout_millis
        options.transaction_timeout_millis = transaction_timeout_millis
        options.schema_lock_acquire_timeout_millis = schema_lock_acquire_timeout_millis

        return options

    def _unset_session(self):
        self.session = None
        return True

    def add_attribute(
        self,
        attribute: Attribute = None,
        return_things: Optional[bool] = False,
    ):
        _log = self.logger
        if not isinstance(attribute, Attribute):
            _log.error(f"{attribute} is NOT an Attribute type!")
            return False

        tx = self.create_transaction(
            tx_type = TransactionType.WRITE,
            save_tx=False,
        )
        fmt = self.format_value_query(attribute.value)
        query = f' $x isa {attribute.label}; $x {fmt};'

        myquery = Query(
            qtype = 'insert',
            string = query,
            target_thing = attribute,
        )

        _log.info(f"Adding attribute {attribute}...")
        answers = self.db_query(myquery, tx, save_tx=False)
        _log.debug(answers)
        try:
            result_query = self.process_query_answers(
                answers, myquery, tx, return_things=return_things
            )
        except TypeDBException:
            _log.error(f"Transaction closed - reopening and trying again")
            tx = self.check_tx(tx=tx)
            answers = self.db_query(myquery, tx, save_tx=False)
            result_query = self.process_query_answers(
                answers, myquery, tx, return_things=return_things
            )
        _log.debug(result_query)
        _log.debug(result_query.answers)
        _log.debug(result_query)
        if not return_things:
            return result_query.answers
        return result_query.answers[0]

    def add_entity(
        self,
        entity: Entity = None,
        return_things: Optional[bool] = False,
    ):
        _log = self.logger
        if not isinstance(entity, Entity):
            _log.error(f"{entity} is NOT an Entity type!")
            return False

        entity = self.check_for_comboid(entity)

        tx = self.create_transaction(
            tx_type = TransactionType.WRITE,
            save_tx = False,
        )

        query = self.get_insert_query_from_entity(entity)
        myquery = Query(
            qtype = 'insert',
            string = query,
            target_thing = entity,
        )

        _log.info(f"Adding Entity {entity}")
        answers = self.db_query(myquery, tx, save_tx=False)
        try:
            result_query = self.process_query_answers(
                answers, myquery, tx, return_things=return_things
            )
        except TypeDBException:
            _log.error(f"Transaction closed - reopening and trying again")
            tx = self.check_tx(tx=tx)
            answers = self.db_query(myquery, tx, save_tx=False)
            result_query = self.process_query_answers(
                answers, myquery, tx, return_things=return_things
            )
        # Require first/last seen on any new relations created
        # entity = self.require_date_seen(result_query.answers[0])
        # return result_query.answers[0]
        # return entity
        if not return_things:
            return result_query.answers
        return result_query.answers[0]

    def add_relation(
        self,
        relation: Relation = None,
        return_things: Optional[bool] = False,
    ):
        _log = self.logger
        # _log.debug(f"relation: {relation.to_dict()}")
        if not isinstance(relation, Relation):
            _log.error(f"{relation} is NOT a Relation type!")
            return False

        # TypeDB requires 'players' be assigned to a Relation before it can
        # be created. If there are no players assigned, make sure there's at
        # least one "dummy" entity in the DB that can be attached to this relation

        if self.debug:
            return_things = True

        relation = self.check_for_comboid(relation)

        if not relation.players:
            ent = Entity(label="empty-ent")
            search_res = self.find_things(ent, limit_get=True, search_mode='lite')
            if not search_res:
                empty_ent = self.add_thing(ent, return_things=True)
            else:
                empty_ent = search_res[0]
            relation.players={'related': [empty_ent]}
        # Make sure all players already exist
        else:
            for role, players in relation.players.items():
                for player in players:
                    existing_ent = self.check_thing_exists(player)
                    if not existing_ent:
                        self.add_thing(player)

        tx = self.create_transaction(
            tx_type = TransactionType.WRITE,
            save_tx = False,
        )

        query = self.get_insert_query_from_relation(relation)

        myquery = Query(
            qtype = 'match_insert',
            string = query,
            target_thing = relation
        )

        _log.info(f"Adding Relation {relation}")

        answers = self.db_query(myquery, tx, save_tx=False)
        try:
            result_query = self.process_query_answers(
                answers, myquery, tx, return_things=return_things
            )
        except TypeDBException:
            _log.error(f"Transaction closed - reopening and trying again")
            tx = self.check_tx(tx=tx)
            answers = self.db_query(myquery, tx, save_tx=False)
            result_query = self.process_query_answers(
                answers, myquery, tx, return_things=return_things
            )
        # Require first/last seen on any new relations created
        if not return_things:
            return result_query.answers
        _log.debug(f"Successfully added relation {pformat(result_query.answers[0].to_dict())}")
        return result_query.answers[0]

    def check_for_comboid(
        self,
        thing: Thing = None,
    ):
        """checks if Thing should have a comboid value, and adds it
        :params thing: Thing to check if comboid is necessary
        :returns thing: updated thing with comboid attribute if needed
        """
        _log = self.logger

        # Get all thing keyattrs
        if not self.thing_keys:
            self.get_thing_keys()
        # If this thing has a key attribute (as all things should at this point)
        if thing.label in self.thing_keys:
            key_label = self.thing_keys[thing.label]
            thing.keyattr = key_label
            # Be sure to set the keyattr
            if thing.keyattr == "comboid":
                # and if it's a comboid...
                if not thing.get_attributes(label="comboid"):
                    # and we don't have any comboid attrs set...
                    comboid = thing.get_comboid()
                    # generate and add one!
                    thing.has.append(comboid)
        return thing
        

    def add_thing(
        self,
        thing: Thing = None,
        dedup_ignore_players: Optional[bool] = False,
        force: Optional[bool] = False,
        return_things: Optional[bool] = False,
    ):
        _log = self.logger
        if not force:
            existing_thing = False
            existing_things = self.check_thing_exists(
                thing,
                dedup_ignore_players=dedup_ignore_players
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
                if isinstance(thing, Attribute):
                    return thing
                _log.debug(f"Looks like {thing} already exists!")
                _log.debug(f"Adding any new details, but not removing any...")
                '''
                existing_thing = self.find_things(existing_thing, search_mode='full')
                existing_copy = copy.deepcopy(existing_thing)
                _log.debug(f"new thing: {thing}")
                merged_thing = existing_copy.merge(**thing)
                _log.debug(f"merged thing: {merged_thing}")
                '''
                pre_time_result = self.update_thing(
                    new_thing=thing, old_thing=existing_thing,
                    return_things=return_things
                )
                if not return_things:
                    return True
                # I'm gonna leave this here for now, but I'm pretty sure
                # limit_get=False is probably wrong - maybe it was required for
                # the require_date_seen stuff?
                # result = self.find_things(things=pre_time_result, limit_get=False)[0]
                result = self.find_things(things=pre_time_result, limit_get=True)[0]
                # result = self.require_date_seen(full_pre_time_result)
                return result

        if isinstance(thing, Attribute):
            result = self.add_attribute(thing, return_things=return_things)
        elif isinstance(thing, Entity):
            if not self.db_name=='road' and not thing.get_attributes('confidence'):
                con = Attribute(label='confidence', value=0.0)
                thing.has.append(con)
            if not thing.get_attributes('date-discovered'):
                now = datetime.now(timezone.utc)
                # now_round = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
                dd = Attribute(label='date-discovered', value=now)
                thing.has.append(dd)
            result = self.add_entity(thing, return_things=return_things)
        elif isinstance(thing, Relation):
            if not self.db_name=='road' and not thing.get_attributes('confidence'):
                con = Attribute(label='confidence', value=0.0)
                thing.has.append(con)
            if not thing.get_attributes('date-discovered'):
                now = datetime.now(timezone.utc)
                # now_round = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
                dd = Attribute(label='date-discovered', value=now)
                thing.has.append(dd)
            result = self.add_relation(thing, return_things=return_things)
        else:
            _log.error(f"Unknown thing passed: {type(thing)} - {thing}")
            return False

        return result

    def attach_attribute(
        self,
        old_thing,
        attr,
        return_things: Optional[bool] = False,
    ):
        _log = self.logger
        _log.debug(f"Attaching {attr} to {old_thing}")
        tx = self.create_transaction(
            tx_type = TransactionType.WRITE,
            save_tx=False,
        )

        query = f'match $th iid {old_thing.iid};'
        fmt = self.format_value_query(attr.value)
        query += f' insert $th has {attr.label} {fmt};'

        myquery = Query(
            qtype = 'match_insert',
            string = query,
            target_thing = old_thing,
        )

        _log.info(f"Adding {attr} to {old_thing}...")
        answers = self.db_query(myquery, tx, save_tx=False)
        try:
            result_query = self.process_query_answers(
                answers, myquery, tx, return_things=return_things
            )
        except TypeDBException:
            _log.error(f"Transaction closed - reopening and trying again")
            tx = self.check_tx(tx=tx)
            answers = self.db_query(myquery, tx, save_tx=False)
            result_query = self.process_query_answers(
                answers, myquery, tx, return_things=return_things
            )
        if not return_things:
            return result_query.answers
        return result_query.answers[0]

    def attach_player(
        self,
        old_thing,
        role,
        player,
        return_things: Optional[bool] = False,
    ):
        _log = self.logger

        player = self.add_thing(player, return_things=True)
        if hasattr(old_thing, 'players') and old_thing.players:
            if role in old_thing.players:
                existing_iids = []
                for existing_player in old_thing.players[role]:
                    if not existing_player.iid in existing_iids:
                        existing_iids.append(existing_player.iid)
                if player.iid in existing_iids:
                    _log.debug(f"Attempting to attach player where one already exists!")
                    _log.debug(f"old_thing: {old_thing}")
                    _log.debug(f"player: {player} (iid: {player.iid})")
                    _log.debug(f"old_thing.players[{role}]: {old_thing.players[role]}")
                    return old_thing

        tx = self.create_transaction(
            tx_type = TransactionType.WRITE,
            save_tx = False,
        )

        query = f'match $rel iid {old_thing.iid};'
        query += f' ${player.label} isa {player.label};'
        query += f' ${player.label} iid {player.iid};'
        '''
        # Removed 2022-09-19 because we added add_thing() to the top, which
        # should guarantee an appropriate iid and make these inserts less...
        # ...verbose.
        for attr in player.has:
            fmt = self.format_value_query(attr.value)
            query += f', has {attr.label} {fmt}'
        query += ';'
        '''

        query += f' insert $rel({role}: ${player.label}) isa {old_thing.label};'

        myquery = Query(
            qtype = 'match_insert',
            string = query,
            target_thing = old_thing,
        )

        _log.debug(f"Adding {role}: {player} to {old_thing}...")
        answers = self.db_query(myquery, tx, save_tx=False)
        # _log.info(f"answers returned!")
        try:
            # _log.info(f"processing answers...")
            result_query = self.process_query_answers(
                answers, myquery, tx, return_things=return_things
            )
        except TypeDBException:
            _log.error(f"Transaction closed - reopening and trying again")
            tx = self.check_tx(tx=tx)
            answers = self.db_query(myquery, tx, save_tx=False)
            result_query = self.process_query_answers(
                answers, myquery, tx, return_things=return_things
            )
        # _log.info(f"answers processed!")
        if not return_things:
            return result_query.answers
        return result_query.answers[0]

    def bulk_add(
        self,
        things: Dict = {},
        force: Optional[bool] = False,
        # return_things: Optional[bool] = False,
    ):
        """
        Used for adding things to the database in bulk.

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
        _log.debug(f"Starting bulk_add process...")
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

    def bulk_add_update(
        self,
        things: List[Thing] = [],
        force: Optional[bool] = False,
        include_meta_attrs: Optional[bool] = False,
    ):
        _log = self.logger
        _log.debug(f"Starting bulk_update add with {len(things)} things!")

        update_things = []

        other_things = []
        key_things = []
        if not self.thing_keys:
            self.get_thing_keys()

        # Find things that have key_attributes
        for thing in things:
            if isinstance(thing, Attribute):
                other_things.append(thing)
                continue
            if not hasattr(thing, 'has'):
                other_things.append(thing)
                continue
            if thing.label not in self.thing_keys:
                other_things.append(thing)
                continue
            keylabel = self.thing_keys[thing.label]

            if keylabel == 'comboid':
                if not thing.get_attributes(label='comboid'):
                    comboid = thing.get_comboid()
                    thing.has.append(comboid)

            found_key = False
            for attr in thing.has:
                if not attr:
                    continue
                if attr.label == keylabel and attr.value:
                    found_key = True
            if found_key:
                key_things.append(thing)
            else:
                _log.warning(
                    f"Attempted to add keyattr thing {thing} "
                    f"with no key attribute!"
                )
                _log.warning(f"{pformat(thing.to_dict())}")
                _log.warning(
                    f"Skipping keyless thing entirely! "
                    f"A KEYATTR THING NEEDS ITS KEY, MAN!"
                )

        if force:
            # If we're forcing the add, we still have to check to make sure
            # we're not trying to add any entities or relations with key
            # attributes that might cause conflicts
            check_things = key_things
        else:
            check_things = other_things + key_things

        new_things, existing_things = self.bulk_check(
            check_things,
            include_meta_attrs=include_meta_attrs
        )
        _log.debug(f"Found {len(new_things)} new things...")
        _log.debug(f"Found {len(existing_things)} existing things...")

        # TODO - FIXME - Remove these DEBUG logs
        for nt in new_things:
            if nt.label in ['hunt', 'enrichment']:
                _log.debug(f"About to ADD NEW {nt.label}!")
                _log.debug(pformat(nt.to_dict()))
        for nt in existing_things:
            if nt[0].label in ['hunt', 'enrichment'] or nt[1].label in ['hunt', 'enrichment']:
                _log.debug(f"About to UPDATE EXISTING {nt[0].label}!")
                '''
                _log.debug(f"new_thing: ")
                _log.debug(pformat(nt[0].to_dict()))
                _log.debug(f"old_thing: ")
                _log.debug(pformat(nt[1].to_dict()))
                '''
        # END FIXME

        if force:
            new_things += other_things

        """
        for tup in existing_things:
            new_thing = tup[0]
            old_thing = tup[1]
            '''
            old_copy = copy.deepcopy(old_thing)
            merged_thing = old_copy.merge(**new_thing)
            update_tuple = (merged_thing, old_thing)
            '''
            update_tuple = (new_thing, old_thing)
            update_things.append(update_tuple)
        """

        if new_things:
            new_things = self._set_confidence(new_things)
            tx = self.create_transaction(
                tx_type = TransactionType.WRITE,
                save_tx = False,
            )

            _log.info(f"Adding {len(new_things)} new things...")
            thing_added_counter = 1
            for thing in new_things:
                if thing_added_counter % 10 == 0:
                    _log.info(f"Added {thing_added_counter} things so far...")
                if thing_added_counter % 20 == 0:
                    # commit every 20 writes
                    # _log.info(f"Committing and recreating transaction")
                    try:
                        tx.commit()
                    except Exception as e:
                        _log.error(f"Failed committing changes: {e}")
                        pass
                    tx = self.create_transaction(tx_type = TransactionType.WRITE, save_tx=False)
                if isinstance(thing, Attribute):
                    fmt = self.format_value_query(thing.value)
                    query = f' $x isa {thing.label}; $x {fmt};'
                    qtype = 'insert'
                elif isinstance(thing, Entity):
                    query = self.get_insert_query_from_entity(thing)
                    qtype = 'insert'
                elif isinstance(thing, Relation):
                    query = self.get_insert_query_from_relation(thing)
                    qtype = 'match_insert'
                    if thing.label in ['hunt', 'relation']:
                        _log.debug(f"ADDING {thing.label} WITH THE FOLLOWING QUERY:")
                        myquery = Query(
                            # qtype = 'insert',
                            qtype = qtype,
                            string = query,
                            target_thing = thing,
                        )
                        _log.debug(pformat(myquery.pp()))
                myquery = Query(
                    # qtype = 'insert',
                    qtype = qtype,
                    string = query,
                    target_thing = thing,
                )
                # answers = self.db_query(myquery, tx, save_tx=False)
                # query_ans = (myquery,answers)
                # all_answers.append(query_ans)
                # ^^^ If we're doing stuff in bulk I don't really care to make it
                #   able to return all the added results. Just search for them after
                #   the fact if that's what you want.
                _log.debug(f"Running query: {myquery.pp()}")
                try:
                    self.db_query(myquery, tx, save_tx=False)
                except Exception as e:
                    _log.error(f"Exception during query: \n{myquery.pp()}")
                    raise e
                thing_added_counter += 1

            try:
                tx.commit()
            except Exception as e:
                _log.error(f"Failed committing changes: {e}")
                pass
            _log.info(f"Finished adding new things!")

        # TODO - Updates should probably be handled in bulk as well - bulk_update instead
        # of a bunch of update_thing calls
        # if update_things:
        if existing_things:
            _log.info(f"Updating {len(existing_things)} things...")
            for update_tuple in existing_things:
                new_thing = update_tuple[0]
                old_thing = update_tuple[1]

                # Make sure new confidence is purged before update
                old_con = old_thing.get_attributes('confidence', first_only=True)
                if old_con:
                    cons = new_thing.get_attributes('confidence')
                    for con in cons:
                        new_thing.has.remove(con)
                    new_thing.has.append(old_con)

                # Make sure discovery date is purged from new_thing before update
                old_dd = old_thing.get_attributes('date-discovered', first_only=True)
                if old_dd:
                    dds = new_thing.get_attributes('date-discovered')
                    for dd in dds:
                        new_thing.has.remove(dd)
                    new_thing.has.append(old_dd)

                self.update_thing(
                        new_thing=new_thing, old_thing=old_thing,
                        return_things=False
                )
            _log.info(f"Finished updating things!")
        _log.debug(f"Done adding and updating things!")
        return True

    def bulk_check(
        self,
        things: List[Thing] = [],
        include_meta_attrs: Optional[bool] = False,
    ):
        """Runs bulk-check for things that may already exist in the database

        :returns: new_things, existing_things
            new_things = List of new Thing objects
            existing_things = List of tuples (new_thing, existing_thing)
        """
        _log = self.logger
        # _log.setLevel("DEBUG")

        new_things = []
        existing_things = []

        if not isinstance(things, list):
            things = [things]

        for thing in things:
            if thing.label in self.thing_keys:
                key_label = self.thing_keys[thing.label]
                thing.keyattr=key_label

        _log.info(f"Searching for {len(things)} existing things...")
        search_thing_tups = []
        for thing in things:
            # if isinstance(thing, Attribute) and thing.label=='ledid':
            # Let's try skipping attribute searches all together and see what happens.
            if isinstance(thing, Attribute):
                continue
            search_thing = copy.deepcopy(thing)
            # If we've got a valid keyattr in play, skip the complicated Relation stuff.
            keyattr_found = False
            if search_thing.label in self.thing_keys:
                key_label = self.thing_keys[search_thing.label]
                safe_copy = copy.deepcopy(search_thing.has)
                for attr in safe_copy:
                    if attr.label!=key_label:
                        search_thing.has.remove(attr)
                if hasattr(search_thing, 'players'):
                    search_thing.players = {}
                keyattr_found=True

            if not keyattr_found and isinstance(search_thing, Relation):
                # Ignore players for things like geoloc, network-service, etc.
                if search_thing.label in search_thing.eq_ignore_players:
                    search_thing.players = {}
                    # thing.players = {}
                # Ignore USELESS players that have no value
                if hasattr(thing, 'players') and thing.players:
                    search_thing.players = {}
                    for role, players in thing.players.items():
                        for player in players:
                            player_copy = copy.deepcopy(player)
                            player_copy.has = []
                            for attr in player.has:
                                if player.label in self.thing_keys:
                                    # hopefully using keyattrs speeds up the process
                                    if attr.label == self.thing_keys[player.label] and attr.value:
                                        player_copy.keyattr = attr.label
                                        player_copy.has = [attr]
                                        break
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

            search_thing_tup = (search_thing, thing)
            search_thing_tups.append(search_thing_tup)

        og_meta = include_meta_attrs
        for stt in search_thing_tups:
            include_meta_attrs = og_meta
            search_thing = stt[0]
            if hasattr(search_thing, 'keyattr'):
                if search_thing.keyattr in thing.meta_attrs:
                    _log.debug(f"SEARCH THING KEYATTR IS A META ATTRIBUTE! BETTER MAKE DAMN SURE WE'RE SEARCHING META ATTRIBUTES!")
                    include_meta_attrs = True
            thing = stt[1]
            try:
                res = self.find_things(
                    search_thing,
                    limit_get=True,
                    search_mode='lite',
                    include_meta_attrs=include_meta_attrs,
                )
            except Exception as e:
                _log.error(f"Something went horribly wrong: {e}")
                '''
                This error should be thrown in the event an unexpected value shows up. For example, when we were getting
                TXT records that were dates instead of string values, this was throwing a fit. There's probably a better
                way to fix this, but since it's such an outlier, I'm just gonna skip things that don't work right for
                the moment.
                '''
                continue
            if not res:
                _log.info(f"thing {thing} not in remote things!")
                if thing not in new_things:
                    _log.info(f"First time seeing new thing {thing}! {thing.to_dict()}")
                    # _log.info(f"{pformat(thing.to_dict())}")
                    new_things.append(thing)
                else:
                    if isinstance(thing, Attribute):
                        continue
                    '''
                    In the event that we're adding two new things at the same time, one of those things might be a
                    relation where we ignore its players during comparison (e.g. network-service, geoloc, etc.).

                    If that's the case, we want to see if the player-ignored version is already in new_things. If it is,
                    we want to pop it from the new_things list, merge the two relations, add the merged thign to
                    new_things, and move along.
                    '''
                    # merged_thing = existing_copy.merge(**thing)
                    _log.debug(f"About to add two of the same thing to new_things!")
                    _log.debug(f"Instead we'll try to merge the two!")
                    first_thing = new_things.pop(new_things.index(thing))
                    _log.debug(f"first_thing: {first_thing}\n\t{pformat(first_thing.to_dict())}")
                    _log.debug(f"second thing: {thing}\n\t{pformat(thing.to_dict())}")
                    merged_thing = first_thing.merge(**thing)
                    _log.debug(f"merged thing: {merged_thing}\n\t{pformat(merged_thing.to_dict())}")
                    thing = merged_thing
                    new_things.append(thing)
            else:
                if isinstance(search_thing, Attribute):
                    continue # We're not going to slate Attributes for existing/updating
                if len(res) > 1:
                    _log.warning(
                        f"Found {len(res)} things when searching for "
                        f"{search_thing.to_dict()}"
                    )
                    _log.warning(f"results: {pformat(res)}")
                    _log.warning(
                        f"This could cause issues!"
                        f" For right now we're just going to pick the first one and say they're the same: "
                        f"{res[0].to_dict()}"
                    )
                _log.debug(f"Getting full details of {res[0]}")
                full_res = self.find_things(
                    res[0],
                    limit_get=True,
                    # search_mode='full',
                    search_mode='lite', # changing this to lite to speed things up
                    include_meta_attrs=include_meta_attrs,
                )[0]
                new_old = (thing, full_res)
                # I'm removing this check against my better judgement because it
                # was assuming that (Relation(label=enrichment, hunt-name=censys-192.168.1.100), Relation(label=enrichment,iid=0x001,hunt-name=censys-192.168.1.100))
                # == (Relation(label=enrichment, hunt-name=censys-192.168.1.222), Relation(label=enrichment,iid=0x003,hunt-name=censys-192.168.1.222))
                # NOTE - adding this back in now that I believe I've fixed it.
                #   The issue apparently was with comparing enrichments that used
                #   a meta attribute (hunt-name) as their keyattr. The tuples
                #   should compare properly now.
                if new_old not in existing_things:
                    _log.debug(f"Adding {new_old} to existing_things")
                    existing_things.append(new_old)
                # else:
                #     _log.debug(f"{new_old} already exists in existing_things: {existing_things}")
        # _log.setLevel("INFO")
        # Add 'date-discovered' to all new_things
        now = datetime.now(timezone.utc)
        # now_round = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
        dd = Attribute(label='date-discovered', value=now)
        for nt in new_things:
            nt.has.append(dd)
        return new_things, existing_things

    def check_db(
        self,
        db_name: str = "",
        client: Optional[TypeDB.core_driver] = None,
    ):
        client = client or self.client
        exists = client.databases.contains(db_name)
        return exists

    def check_session(
        self,
        client: Optional[TypeDB.core_driver] = None,
        session: Optional[object] = None,
        db_name: Optional[str] = None,
        save_session: Optional[bool] = True,
        options: Optional[TypeDBOptions] = None,
    ):
        _log = self.logger

        session = session or self.session
        if not session:
            session = self.create_session(options=options)

        # If db_name is not provided, we assume self.db_name is our target.
        # However, there are instances where session.database_name() != self.db_name
        # and in those cases we need to make sure they're equal.

        db_name = db_name or self.db_name
        if not session.database_name() == db_name:
            session = self.create_session(
                db_name=db_name,
                save_session=save_session,
                options=options,
            )
            self.session_timer = int(datetime.now().timestamp())
            return session

        timecheck = int(datetime.now().timestamp()) - self.session_timer
        if not session.is_open() or timecheck >= 88:
            if session.is_open():
                session.close()
            _log.debug(f"Session supplied was not open! Recreating!")
            session = self.create_session(
                client=client,
                db_name=db_name,
                session_type=session.type,
                save_session=save_session,
                options=options,
            )
            self.session_timer = int(datetime.now().timestamp())
        return session

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
            # Set keyattr (string of label type) because it's not set inherently
            # when a new Thing is created
            thing.keyattr = key_label
            # Remove everything that isn't the keyattr before searching
            for attr in thing.has:
                if attr.label!=key_label:
                    search_thing.has.remove(attr)
            if hasattr(search_thing, 'players'):
                # We just want the key attribute - players make it messy
                search_thing.players = {}

        # Generate comboid attribute for Things that need it
        if keyattr_thing and thing.keyattr == "comboid":
            if not search_thing.get_attributes(label='comboid'):
                comboid = thing.get_comboid()
                # add comboid to the search thing
                search_thing.has.append(comboid)
                # also add comboid to the original thing in the event that
                # search returns nothing and we want to add something brand new
                thing.has.append(comboid)

        # If we already have a keyattr thing, skip all this mess.
        # We already have the key we need.
        if not keyattr_thing:
            if isinstance(thing, Entity) or isinstance(thing, Relation):
                for attr in thing.has:
                    if attr.label in thing.meta_attrs:
                        if attr in search_thing.has:
                            search_thing.has.remove(attr)
                # If it's not an empty-ent and has no useful attributes, it's
                # junk. It's better to say it already exists here, than
                # to say it doesn't exist and keep running checks.
                # if isinstance(thing, Entity) and not thing.label=='empty-ent':
                #     if not search_thing.has:
                #         return True
                # NOTE - I take it back. Returning True is not the way to go.

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

        _log.debug(f"Fast-searching for existing thing...")
        remote_thing = self.find_things(
            search_thing,
            limit_get=True,
            include_meta_attrs=include_meta_attrs,
            search_mode='lite'
        )
        if not remote_thing:
            _log.debug(f"Nothing found!")
            return False
        if len(remote_thing) > 1:
            _log.warning(f"Uh oh.. We searched for {search_thing} and got more than one result!")
            _log.warning(f"search_thing: {search_thing.to_dict()}")

        return remote_thing
        """
        _log.debug(f"full-searching for existing {remote_thing}...")
        full_remote_thing = self.find_things(
            remote_thing,
            limit_get=True,
            search_mode='full'
        )
        if len(full_remote_thing) > 1:
            _log.warning(f"Uh oh.. We searched for {search_thing} and got more than one result!")
            _log.warning(f"search_thing: {search_thing.to_dict()}")
        return full_remote_thing
        """

    def check_tx(
        self,
        db_name: Optional[str] = "",
        tx: Optional[object] = None,
        client: Optional[TypeDB.core_driver] = None,
        session: Optional[object] = None,
        save_tx: Optional[bool] = True,
        options: Optional[TypeDBOptions] = None,
    ):
        _log = self.logger

        db_name = db_name or self.db_name
        tx = tx or self.tx

        if not tx:
            tx = self.create_transaction(
                client=client,
                db_name=db_name,
                session=session,
                save_tx=save_tx,
                options=options,
            )

        if not client:
            client=self.client

        if not session:
            session=self.session

        if not session:
            session = self.create_session(
                db_name=db_name,
                save_session=save_tx,
                options=options,
            )

        # If there's a session mismatch, close the session
        if session.database_name() != db_name:
            _log.info(
                f"Session mismatch. Looking for {db_name} got "
                f"{session.database_name()}! Creating new session."
            )
            tx.close()
            session.close()
            session = self.create_session(db_name=db_name)
            if not self.session.is_open():
                self.session = session

        timecheck = int(datetime.now().timestamp()) - self.tx_timer
        if not tx.is_open() or timecheck >= 90:
            if tx.is_open():
                tx.close()
            _log.debug(f"Transaction supplied was not open! Recreating!")
            new_tx = self.create_transaction(
                tx_type=tx.transaction_type,
                client=client,
                session=session,
                db_name=str(session.database_name()),
                save_tx=save_tx,
                options=options,
            )
            tx = new_tx
        return tx

    def concept_to_thing(
        self,
        concept: object = None,
        tx: object = None,
        search_mode: Optional[str] = 'full',
        save_tx: Optional[bool] = True,
        get_schema: Optional[bool] = False,
        options: Optional[TypeDBOptions] = None,
    ):
        """
        Converts database query response into a Thing Object.

        :param concept: Concept response provided by the database
        :param tx: Transaction to use for subsequent DB requests
        :param search_mode: "full", "lite", or "no_backtrace".
            - "full" (Default) pulls down all details of all subset Things. (e.g. if you get
            a Relation with 3 Entities, it will populate ALL attributes associated
            with each entity). But the most taxing part is when it also populates
            the next level of relations and their associated attributes as well.
            - "lite" only returns the top-level object discovered in the current
            concept with its immediate Attributes, but does not attempt to enrich
            any next-level Entities or Relations
            - "no_backtrace" is only for Relation things. It gets all attributes
                    of the given Relation, all roles & sub-entities, but no attributes
                    of those entities, nor does it cause the entities to find all
                    Relations associated with each entity

        """
        _log = self.logger
        if not self.thing_keys:
            self.get_thing_keys()
        thing = None

        if concept.is_thing():
            concept_type = concept.get_type()
        elif concept.is_type():
            concept_type = concept

        label = concept_type.get_label().name
        if not concept_type.is_role_type():
            iid = concept.get_iid()
            inferred = concept.is_inferred()

        if concept_type.is_attribute_type():
            if concept.is_thing():
                value = concept.get_value()
                if isinstance(value, datetime):
                    value = value.astimezone(timezone.utc)
                    value = format_date(value)
                elif isinstance(value, str):
                    value = value.replace("\\\"", "\"")
            elif concept.is_type():
                value = ""
            thing = Attribute(
                iid = iid,
                inferred = inferred,
                label=label,
                value=value,
            )
        elif concept_type.is_entity_type():
            thing = Entity(
                iid = iid,
                inferred = inferred,
                label = label,
            )
            # Need to strip auto-generated ledid when pulling from db
            thing = self.ledid_del(thing)
        elif concept_type.is_relation_type():
            thing = Relation(
                iid = iid,
                inferred = inferred,
                label = label,
            )
            # Need to strip auto-generated ledid when pulling from db
            thing = self.ledid_del(thing)
        elif concept_type.is_role_type():
            thing = Role(
                label=label,
            )
        else:
            _log.error(f"Unknown concept type: {concept_type}!")
            raise

        if get_schema:
            _log.info(f"populating thing from schema...")
            thing = self.populate_thing_from_schema(thing)
            _log.info(f"thing schema populated!")

        elif isinstance(thing, Entity):
            # _log.info(f"handling entity...")
            remote_concept = concept
            # rel_no_backtrace only invoked when calling concept_to_thing() from
            # INSIDE concept_to_thing() - while processing a Relation
            # So this effectively says, if your search_mode is set to lite,
            # no_backtrace, or full, make sure you're getting the entities' attrs.

            # removing rel_no_backtrace check because entities should have
            # their attributes retrieved, just like relations do.
            # if search_mode != "rel_no_backtrace":
            thing.has = []
            thing_has = remote_concept.get_has(tx)
            for attr in thing_has:
                h = self.concept_to_thing(attr, tx, search_mode=search_mode)
                thing.has.append(h)
                if h.label == 'ledid':
                    thing = self.ledid_set(thing)
            # If lite is set on an ent, don't get relations. Otherwise, get them.
            if search_mode == "no_backtrace" or search_mode=="full":
                thing_rels = remote_concept.get_relations(tx)
                for rel in thing_rels:
                    rel_type = rel.get_type()
                    label = rel_type.get_label().name
                    iid = rel.get_iid()
                    inferred = rel.is_inferred()
                    rel_has = rel.get_has(tx)
                    has = []
                    for attr in rel_has:
                        h = self.concept_to_thing(attr, tx, search_mode=search_mode)
                        has.append(h)
                    new_rel = Relation(
                        iid=iid,
                        has=has,
                        label=label,
                        inferred=inferred,
                    )
                    thing.relations.append(new_rel)
            # _log.info(f"entity handled!")

        elif isinstance(thing, Role):
            remote_concept = concept_type
            scope = concept_type.get_label().scope
            thing.scope = scope
            scoped_name = concept_type.get_label().scoped_name()
            thing.scoped_name = scoped_name

        elif isinstance(thing, Relation):
            # _log.info(f"processing relation {thing}...")
            remote_concept = concept
            thing.has = []
            thing_has = remote_concept.get_has(tx)
            for has in thing_has:
                h = self.concept_to_thing(has, tx, search_mode=search_mode)
                thing.has.append(h)
                if h.label == 'ledid':
                    thing = self.ledid_set(thing)

            if search_mode == "full" or search_mode == "no_backtrace":
                # _log.info(f"Getting full scope relations for {thing}...")
                thing_rels = remote_concept.get_relations(tx)
                if search_mode == 'no_backtrace':
                    search_mode = 'rel_no_backtrace'
                for rel in thing_rels:
                    rel_type = rel.get_type()
                    label = rel_type.get_label().name
                    iid = rel.get_iid()
                    inferred = rel.is_inferred()
                    # previously removed from no_backtrace
                    rel_has = rel.get_has(tx)
                    has = []
                    for attr in rel_has:
                        h = self.concept_to_thing(attr, tx, search_mode="lite")
                        has.append(h)
                    # end no_backtrace removed section
                    new_rel = Relation(
                        iid=iid,
                        has=has,
                        label=label,
                        inferred=inferred,
                    )
                    thing.relations.append(new_rel)
                thing.players = {}
                # ! thing_players = remote_concept.get_players_by_role_type()
                thing_players = remote_concept.get_players(tx)
                player_dict = {}
                for role_concept, ent_concepts in thing_players.items():
                    role = self.concept_to_thing(role_concept, tx, search_mode=search_mode)
                    player_dict[role.label] = []
                    for ent_concept in ent_concepts:
                        entity = self.concept_to_thing(
                            ent_concept,
                            tx,
                            search_mode=search_mode,
                        )
                        player_dict[role.label].append(entity)
                thing.players = player_dict
            # _log.info(f"relation {thing} processed!")
        if thing.label in self.thing_keys:
            thing.keyattr = self.thing_keys[thing.label]
        return thing

    def convert_hostname_to_domain(
        self,
        db_name: Optional[str] = "",
    ):
        """Convert hostnames to domains
        Given all the hostnames in a  database, use regex to convert them into
        the most-likely domains.

        NOTE - this doesn't get crazy. It doesn't use https://www.publicsuffix.org/list/
            it just looks for the most-likely candidate for a domain.

        :param db_name: Optional override of the database used for converting hostnames
        """
        _log = self.logger
        if db_name:
            self.db_name = db_name

        regex = r"(?:[-a-zA-Z0-9._*]+\.)?([-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,63}\b)+"
        pattern = re.compile(regex)

        bulk_domains = {
            'entities': [],
            'relations': [],
        }
        domains = []
        now = Attribute(label='date-seen', value=datetime.now(timezone.utc))

        _log.info(f"Creating domains from hostnames...")

        so = Entity(label='hostname')
        hostnames = self.find_things(so, search_mode='no_backtrace')
        for hostname in hostnames:
            # Make sure we have a valid hostname string
            hostname_str = hostname.keyval
            if not hostname_str:
                continue
            # Make sure we haven't added this domain already
            domain_exists = False
            for domain in domains:
                if hostname_str.endswith(domain):
                    domain_exists = True
                    break
            if domain_exists:
                    continue
            # Parse out the domain string
            res = re.search(pattern, hostname_str)
            if not res:
                continue
            domain_name = res[1]
            # Add the domain to the list of domains parsed
            if domain_name not in domains:
                domains.append(domain_name)
            # Build the domain entity
            has = [
                Attribute(label='domain-name', value=domain_name),
                Attribute(label='note', value=f'parsed from {hostname_str}'),
            ]
            domain = Entity(label='domain', has=has)
            # Check to see if the domain already exists in our DB
            exists = self.find_things(domain, search_mode='lite')
            if exists:
                # If the hostname is already a false-postiive, make sure 
                # the domain is too.
                domain = exists[0]
                hostname_con = hostname.get_attributes('confidence', first_only=True)
                if hostname_con and hostname_con.value == -1:
                    domain_con = domain.get_attributes('confidence', first_only=True)
                    if domain_con and domain_con.value != -1:
                        self.replace_attribute(domain, hostname_con)
                continue
            # If everything checks out, add to our bulk list
            if domain not in bulk_domains['entities']:
                bulk_domains['entities'].append(domain)
                if hasattr(hostname, 'relations'):
                    for rel in hostname.relations:
                        if rel.label=='enrichment':
                            if not 'related' in rel.players:
                                rel.players['related'] = [domain]
                            else:
                                rel.players['related'].append(domain)
                        bulk_domains['relations'].append(rel)

        _log.info(f"Adding {len(bulk_domains['entities'])} new domains...")
        self.bulk_add(bulk_domains)
        _log.info(f"Done converting hostnames to domains!")
        return True

    def create_client(
        self,
        db_server: Optional[str] = '',
        # ! threads: Optional[str] = '',
        save_client: Optional[bool] = True,
        name: Optional[str] = '',
        cloud_user: Optional[str]= "",
        cloud_pass: Optional[str] = "",
        cloud_tls: Optional[bool] = True,
    ):
        _log = self.logger
        db_server = db_server or self.db_server
        # ! threads = threads or self.parallelisation
        gcc = self.generic_client_counter
        _log.info(f"Opening client for {db_server}")
        if 'typedb.com:1729' in db_server:
            if not cloud_user:
                cloud_user = self.cloud_user
            if not cloud_pass:
                cloud_pass = self.cloud_pass
            if not cloud_user and cloud_pass:
                _log.error(f"valid cloud_user and cloud_pass required to access cloud instance")
                return None
            # // _log.info(f"Setting credential: {cloud_user}:{cloud_pass}")
            creds = TypeDBCredential(cloud_user, cloud_pass, tls_enabled=cloud_tls)
            client = TypeDB.cloud_driver(db_server, creds)
        else:
            client = TypeDB.core_driver(db_server)
        generic_client_name = f"drone_{gcc}"
        client_name = name or generic_client_name
        client.name = client_name
        if save_client:
            if not self.client:
                self.client = client
        # ! _log.debug(f"Created DB Client {client.name} for {db_server} with {threads} threads!")
        _log.debug(f"Created DB Client {client.name} for {db_server}!")
        # self.client = client # DONT DO THIS - it causes RPC channel errors with LEDMGMT
        # return self.client
        return client

    def create_db(
        self,
        db_name: Optional[str] = "",
        client: Optional[TypeDB.core_driver] = None,
    ):
        client = client or self.client
        db_name = db_name or self.db_name
        client.databases.create(db_name)
        return True

    def create_session(
        self,
        session_type: Optional[SessionType] = SessionType.DATA,
        client: Optional[TypeDB.core_driver] = None,
        db_name: Optional[str] = '',
        save_session: Optional[bool] = True,
        options: Optional[TypeDBOptions] = None,
    ):
        _log = self.logger
        client = client or self.client
        if not client:
            client = self.create_client()
        db_name = db_name or self.db_name
        session = client.session(db_name, session_type, options)
        session.on_close(self._unset_session)
        if save_session:
            if self.session:
                if self.session.is_open():
                    self.session.close()
            self.session = session
            self.session_timer = int(datetime.now().timestamp())
        return session

    def create_transaction(
        self,
        tx_type: Optional[TransactionType] = TransactionType.READ,
        client: Optional[TypeDB.core_driver] = None,
        session: Optional[object] = None,
        db_name: Optional[str] = "",
        save_tx: Optional[bool] = True,
        options: Optional[TypeDBOptions] = None,
    ):
        """
        Creates a transaction using currently-opened self.client and self.session
        """

        _log = self.logger
        _log.debug(f"Creating transaction...")

        client = client or self.client
        if not client:
            client = self.create_client()

        # If a session was not explicitly passed, nuke all possible sessions
        if not session:
            session = self.session
            if session:
                db_name = db_name or str(session.database_name())
                session.close()
                if self.session:
                    if self.session.is_open():
                        self.session.close()
                session = self.create_session(db_name=db_name, options=options)
            else:
                session = self.create_session(db_name=db_name, options=options)

        updated_session = self.check_session(
            client=client,
            session=session,
            db_name=db_name,
            save_session=save_tx,
            options=options
        )
        tx = updated_session.transaction(tx_type, options)

        # Save it for future referencing until timeout or explicitly closed
        if save_tx:
            if self.tx:
                if self.tx.is_open():
                    self.tx.close()
            self.tx = tx
            self.tx_timer = int(datetime.now().timestamp())

        _log.debug(f"Opened {tx_type} with {session.type}!")
        return tx

    def db_query(
        self,
        myquery: Query = None,
        tx: Optional[object] = None,
        save_tx: Optional[bool] = True,
        options: Optional[TypeDBOptions] = None,
    ):
        """
        Query the database

        session_type, and options are optional, but if you want to
        read the SCHEMA or WRITE anything, you should explicitly define them
        in case the transaction needs to be reopened before running.

        :params myquery: Query object with Query.string set to the query, and
            search_mode set to 'lite', 'no_backtrace', or 'full'
        :returns: answers parsed from DB
        """

        _log = self.logger
        # _log.info(f"options: {options}")

        simple_queries = ["match", "insert"]
        # if tx not explicitly defined (as in WRITE operations)
        if not tx:
            tx = self.tx
            tx = self.check_tx(tx=tx, save_tx=save_tx, options=options)
            # _log.debug(f"tx check from db_query")
        action = self._get_tx_action_from_qtype(myquery.qtype, tx)

        # simple queries need to prepend the query type before executing
        if myquery.qtype in simple_queries:
            tql = myquery.qtype + myquery.string
        else:
            tql = myquery.string

        _log.debug(f"Executing {myquery.qtype} TypeQL Query: \n{myquery.pp()}")
        # if options:
        #     _log.info(f"options: {options.__dict__}")
        if options:
            query_options = TypeDBOptions()
            if options.explain:
                query_options.explain=True
            try:
                answers = action(tql, options=query_options)
            except TypeDBDriverException as e:
                _log.error(f"Error running tql: {e}")
                _log.error(f"tql: \n{tql}")
                _log.error(f"query_options: \n{query_options}")
                raise e
        else:
            try:
                answers = action(tql)
            except TypeDBDriverException as e:
                _log.error(f"Error running tql: {e}")
                _log.error(f"tql: \n{tql}")
                raise e
        return answers

    def delete_db(
        self,
        db_name: str = "",
        client: Optional[TypeDB.core_driver] = None,
    ):
        _log = self.logger
        _log.info(f"Deleting {db_name}...")
        client = client or self.client
        if not client:
            client = self.create_client()
        db_name = db_name or self.db_name
        exists = self.check_db(db_name)
        if not exists:
            _log.info(f"You cannot delete what does not yet exist!")
            return True
        client.databases.get(db_name).delete()
        return True

    def delete_thing(
        self,
        thing: Thing = None,
        db_name: Optional[str] = '',
        return_things: Optional[bool] = False,
    ):
        _log = self.logger
        if not thing.iid:
            _log.error(f"Deletion requires a thing to have an IID!")
            return False

        if not db_name:
            tx = self.create_transaction(
                tx_type = TransactionType.WRITE,
                save_tx=False,
            )
        else:
            tx = self.create_transaction(
                tx_type = TransactionType.WRITE,
                save_tx=False,
                db_name=db_name,
            )

        query = f'match $th iid {thing.iid}; delete $th isa thing;'
        myquery = Query(
            qtype = 'delete',
            string = query,
        )

        _log.info(f"Deleting {thing}...")
        answers = self.db_query(myquery, tx, save_tx=False)
        try:
            result_query = self.process_query_answers(
                answers, myquery, tx, return_things=return_things
            )
        except TypeDBException:
            _log.error(f"Transaction closed - reopening and trying again")
            tx = self.check_tx(tx=tx)
            answers = self.db_query(myquery, tx, save_tx=False)
            result_query = self.process_query_answers(
                answers, myquery, tx, return_things=return_things
            )
        if not return_things:
            return result_query.answers
        return result_query.answers[0]

    def detach_attribute(
        self,
        old_thing,
        attr,
        return_things: Optional[bool] = False,
    ):
        _log = self.logger
        tx = self.create_transaction(
            tx_type = TransactionType.WRITE,
            save_tx=False,
        )

        query = f'match $th iid {old_thing.iid};'
        fmt = self.format_value_query(attr.value)
        query += (
            f' $th has {attr.label} ${attr.label}; '
            f'${attr.label} = {fmt};'
        )
        query += f' delete $th has ${attr.label};'

        myquery = Query(
            qtype = 'match_delete',
            string = query,
            target_thing = old_thing,
        )

        _log.info(f"Removing {attr} from {old_thing}...")
        answers = self.db_query(myquery, tx, save_tx=False)
        try:
            result_query = self.process_query_answers(
                answers, myquery, tx, return_things=return_things
            )
        except TypeDBException:
            _log.error(f"Transaction closed - reopening and trying again")
            tx = self.check_tx(tx=tx)
            answers = self.db_query(myquery, tx, save_tx=False)
            result_query = self.process_query_answers(
                answers, myquery, tx, return_things=return_things
            )
        if isinstance(result_query, list):
            return result_query.answers[0]
        else:
            return result_query.answers

    def detach_player(
        self,
        old_thing,
        role,
        player,
        return_things: Optional[bool] = False,):
        _log = self.logger
        tx = self.create_transaction(
            tx_type = TransactionType.WRITE,
            save_tx = False,
        )

        query = f'match $rel iid {old_thing.iid};'
        query += f' ${player.label} isa {player.label}'
        for attr in player.has:
            fmt = self.format_value_query(attr.value)
            query += f', has {attr.label} {fmt}'
        query += ";"
        query += f' delete $rel ({role}: ${player.label});'

        myquery = Query(
            qtype = 'match_delete',
            string = query,
            target_thing = old_thing,
        )

        _log.info(f"Removing {role}: {player} from {old_thing}...")
        answers = self.db_query(myquery, tx, save_tx=False)
        try:
            result_query = self.process_query_answers(
                answers, myquery, tx, return_things=return_things
            )
        except TypeDBException:
            _log.error(f"Transaction closed - reopening and trying again")
            tx = self.check_tx(tx=tx)
            answers = self.db_query(myquery, tx, save_tx=False)
            result_query = self.process_query_answers(
                answers, myquery, tx, return_things=return_things
            )
        if isinstance(result_query, list):
            return result_query.answers[0]
        else:
            return result_query.answers

    def find_things(
        self,
        things: Union[List[Thing], Thing] = [],
        db_name: Optional[str] = '',
        limit_get: Optional[bool] = True,
        or_mod: Optional[Dict] = {},
        sort_mod: Optional[Dict] = {},
        search_mode: Optional[str] = "full",
        include_meta_attrs: Optional[bool] = False,
        tx: Optional[object] = None,
        save_tx: Optional[bool] = True,
        options: Optional[TypeDBOptions] = None,
    ):
        """

        Find and return things from the database. Returns list of objects.
        Returns False if failed.

        :param things: List of Thing objects or Dictionaries to search DB for
            Required
        :param limit_get: If True, limit the objects returned specifically to the
            object labels requested instead of all variables in the search.
        :param or_mod: If set, generates 'or' text disjunction patterns.
            format: {
                'label': 'hunt-name',
                'action': 'contains',
                'values': ['censys', 'shodan'],
            }
        :param sort_mod: If set, sorts the results based on sort_mod params:
            format: {
                'label': 'hunt-name',
                'sort_method': 'asc',
                'offset': 0,
                'limit': 10,
            }
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
        :param include_meta_attrs: For Relations and Entities, if set to True,
            makes sure meta attributes such as date-seen, note, and tag are NOT
            included in the search QUERY itself.

        """

        _log = self.logger

        if not db_name:
            db_name = self.db_name

        # _log.info(f"options: {options}")
        # Is this check screwing things up? Leaving it for now.
        current_tx = tx or self.tx
        if current_tx and not current_tx.transaction_type == TransactionType.READ:
            current_tx = self.create_transaction()
        tx = self.check_tx(
            tx=current_tx,
            db_name=db_name,
            save_tx=save_tx,
            options=options
        )

        # Make sure key attributes are populated for returning results
        if not self.thing_keys:
            self.get_thing_keys()

        result_things_iids = []

        if not isinstance(things, list):
            things = [things]

        # Regardless of whether or not we want to check for meta attributes,
        # we never want to check for specific ledid attributes. It's much faster
        # to check for iid's in that case. So if include_meta_attrs = True, we
        # want to make sure the ledid is stripped before going that route.
        if include_meta_attrs:
            for thing in things:
                self.ledid_del(thing)

        search_things = []
        for thing in things:
            if hasattr(thing, 'keyattr'):
                if not thing.keyattr:
                    if thing.label in self.thing_keys:
                        thing.keyattr = self.thing_keys[thing.label]
                # * If we want to search using comboid, we should make sure the
                # * original object passed to find_things() has it generated
                # * already. Otherwise, we have no way of searching for all
                # * things containing a specific attribute.
                # If keyattr=='comboid' make sure we have a comboid attribute attached
                # // if thing.keyattr == 'comboid':
                    # // if not thing.get_attributes(label='comboid'):
                        # // comboid = thing.get_comboid()
                        # // thing.has.append(comboid)

            # Make a safe copy of the thing we're searching for manipulation
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
        _log.debug(f"Searching for things {things}")
        _log.debug(f"limit_get={limit_get}")
        _log.debug(f"or_mod: {pformat(or_mod)}")
        _log.debug(f"sort_mod: {pformat(sort_mod)}")
        final_query = False
        for thing in search_things:
            blank_query = Query()
            query = copy.deepcopy(blank_query)
            query.qtype = "match"
            query.target_thing = thing
            query.search_mode = search_mode
            query.string = self.get_query_from_thing(
                thing,
                limit_get=limit_get,
                or_mod=or_mod,
                sort_mod=sort_mod,
            )
            if not query.string:
                _log.error(f"Unable to build string for {thing}!")
                continue
            answers = self.db_query(query, tx, save_tx, options=options)
            try:
                response_query = self.process_query_answers(
                    answers, query, tx, return_things=True
                )
            except TypeDBException:
                _log.info(f"Transaction closed - reopening and trying again")
                tx = self.check_tx(tx=tx)
                answers = self.db_query(query, tx, save_tx=False, options=options)
                response_query = self.process_query_answers(
                    answers, query, tx, return_things=True
                )

            # if limit_get set, we only want the explicit things we're searching for
            if limit_get and hasattr(response_query, 'answers'):

                # Get valid thing.labels
                tx = self.check_tx()
                concepts = tx.concepts
                valid_labels = ['thing']
                # ! thing_type = concepts.get_thing_type(thing.label)
                thing_type = None
                if isinstance(thing, Attribute):
                    thing_type = concepts.get_attribute_type(thing.label).resolve()
                    if not thing_type:
                        _log.warning(f"{thing.label} is not a valid Attribute!")
                        thing_type = concepts.get_relation_type(thing.label).resolve()
                        if not thing_type:
                            thing_type = concepts.get_entity_type(thing.label).resolve()
                            if not thing_type:
                                _log.warning(
                                    f"Unable to determine proper type of {thing.label}. Skipping!"
                                )
                                continue
                            else:
                                _log.warning(f"{thing.label} is an Entity!")
                        else:
                            _log.warning(f"{thing.label} is a Relation!")

                elif isinstance(thing, Entity):
                    thing_type = concepts.get_entity_type(thing.label).resolve()
                    if not thing_type:
                        _log.warning(f"{thing.label} is not a valid Entity!")
                        thing_type = concepts.get_relation_type(thing.label).resolve()
                        if not thing_type:
                            thing_type = concepts.get_attribute_type(thing.label).resolve()
                            if not thing_type:
                                _log.warning(
                                    f"Unable to determine proper type of {thing.label}. Skipping!"
                                )
                                continue
                            else:
                                _log.warning(f"{thing.label} is an Attribute!")
                        else:
                            _log.warning(f"{thing.label} is a Relation!")

                elif isinstance(thing, Relation):
                    thing_type = concepts.get_relation_type(thing.label).resolve()
                    if not thing_type:
                        _log.warning(f"{thing.label} is not a valid Relation!")
                        thing_type = concepts.get_entity_type(thing.label).resolve()
                        if not thing_type:
                            thing_type = concepts.get_attribute_type(thing.label).resolve()
                            if not thing_type:
                                _log.warning(
                                    f"Unable to determine proper type of label {thing.label}. Skipping!"
                                )
                                continue
                            else:
                                _log.warning(f"{thing.label} is an Attribute!")
                        else:
                            _log.warning(f"{thing.label} is an Entity!")

                # ; if no thing_type then this might be a generic object retrieved by iid
                if thing_type:
                    thing_type_subs = thing_type.get_subtypes(tx)
                    for tts in thing_type_subs:
                        valid_labels.append(tts.get_label().name)
                    resp_copy = copy.deepcopy(response_query)
                    for rc in resp_copy.answers:
                        if not rc.label in valid_labels:
                            response_query.answers.remove(rc)

            if not final_query:
                final_query = response_query
            else:
                final_query.answers += response_query.answers

        if not final_query:
            return []
        # Before returning, set the keyattr value if it's appropriate to do so
        keys_set = []
        for thing in final_query.answers:
            if not thing.label in self.thing_keys:
                keys_set.append(thing)
                continue
            thing.keyattr = self.thing_keys[thing.label]
            keys_set.append(thing)
        final_query.answers = keys_set
        _log.debug(f"Found results: {final_query.answers}")
        return final_query.answers

    def format_value_query(self,val):
        _log = self.logger
        if isinstance(val, str):
            pos_int = re.match(r"^-?(\d+(\.|\s)?)+$", val)
            long_enough = False
            # 8 because we'll assume the shortest possible date we want to deal
            # with is formatted like 20220611
            if len(val) >= 8:
                long_enough = True
            if long_enough and not pos_int:
                dto = None
                try:
                    dto = dateutil.parser.parse(val)
                except Exception as ex:
                    pass
                if dto:
                    test = dto.strftime("%Y")
                    # NOTE - THIS WILL HAVE TO BE CHANGED IN 78 YEARS! ;)
                    if test.startswith("20"):
                        val = dto
        if isinstance(val, datetime):
            if not val.tzinfo:
                val = val.replace(tzinfo=timezone.utc)
            val = val.strftime("%Y-%m-%dT%H:%M:%S")
        elif isinstance(val, str):
            val = re.sub(r"(?<!\\)\"", "\\\"", val)
            if len(val) >= 62000:
                val = val[0:62000]
                _log.info(f"Truncating long string to 62000 bytes!")
            val = f'"{val}"'
        elif isinstance(val, bool):
            val = str(val).lower()
        elif isinstance(val, int):
            val = round(float(val),2)
        elif isinstance(val, float):
            val = round(float(val),2)
        return val

    def get_active_dbs(
        self,
    ):
        """Returns only 'active' DBs from the DB set.
        """
        _log = self.logger

        all_dbs = []
        active_dbs = []
        dbs = self.get_all_dbs()
        for dbo in dbs:
            db = str(dbo)
            if db != 'road':
                all_dbs.append(db)

        for db_name in all_dbs:
            # Look for active hunts
            ah = Attribute(label='hunt-active', value=True)
            hunt = Relation(label='hunt', has=[ah])
            self.db_name = db_name
            try:
                active_hunt = self.find_things(
                    hunt,
                    search_mode='lite',
                    include_meta_attrs=True,
                )
            except Exception as e:
                _log.error(f"Error looking for hunt-active in {self.db_name}: {e}")
                active_hunt = False
            if active_hunt:
                active_dbs.append(db_name)

        return active_dbs


    def get_all_dbs(
        self,
        client: Optional[TypeDB.core_driver] = None,
        readable: Optional[bool] = False
    ):
        client = client or self.client
        dbs = client.databases.all()
        if readable:
            res = []
            for db in dbs:
                res.append(db.name())
            dbs = res
        return dbs

    def get_db(
        self,
        db_name: str = "",
        client: Optional[TypeDB.core_driver] = None,
    ):
        """
        Retrieve a database with the given name.

        :returns: Database
        """
        client = client or self.client
        db = client.databases.get(db_name)
        return db

    def get_insert_query_from_entity(
        self,
        thing: Entity = None,
    ):
        """
        Given an Entity object, use its properties to craft a proper TypeDB query.

        :param thing: Entity object for building the query
        :param limit_get: Set this to True if you only want to return the top-level
            object you're feeding the query builder.
        """

        # NOTE - If you're thinking about converting this to ignore USELESS
        # entities the same way the Relation query builder does, DON'T!
        # There are some cases where meta entities are required (like the road).

        tql = f' ${thing.label} isa {thing.label}'
        if hasattr(thing, 'has'):
            if thing.has:
                for attr in thing.has:
                    tql += f', has {attr.label}'
                    if not attr.value is None:
                        fmt_val = self.format_value_query(attr.value)
                        tql += f' {fmt_val}'
        elif hasattr(thing, 'value'):
            fmt_val = self.format_value_query(thing.value)
            tql += f"; ${thing.label} {fmt_val}"
        tql += ";"

        return tql

    def get_insert_query_from_relation(
        self,
        thing: Relation = None,
    ):
        """
        Given a Relation object, use its properties to craft a proper TypeDB query.

        :param thing: Relation object for building the query
        :param limit_get: Set this to True if you only want to return the top-level
            object you're feeding the query builder.
        """
        _log = self.logger
        acceptable_junk_ents = [
            'empty-ent',
            'actors',
            'archives',
            'index',
            'scratchpad'
        ]
        _log.debug(f"Getting INSERT QUERY FROM RELATION")
        _log.debug(f"thing: {thing}")
        if thing.players:
            tql = f'match'
            role_var_list = []
            _log.debug(f"thing.players: {thing.players}")
            for role, players in thing.players.items():
                for player in players:
                    player_has_valuable_attr = False
                    index_var = players.index(player)
                    q_var = f"{role}_{player.label}_{index_var}"
                    tql_temp = f' ${q_var} isa {player.label}'
                    if isinstance(player, Attribute):
                        _log.debug(f"Player is ATTRIBUTE!: {player}")
                    if player.has:
                        for attr in player.has:
                            if attr.label in player.meta_attrs:
                                continue
                            player_has_valuable_attr = True
                            _log.debug(f"{player} player attr: {attr}")
                            tql_temp += f', has {attr.label}'
                            if hasattr(attr, 'value'):

                                attr_val = self.format_value_query(attr.value)

                                tql_temp += f' {attr_val}'
                            else:
                                _log.warning(
                                    f"Attribute should always have a value: {attr}"
                                )

                    tql_temp += ";"
                    if not player.label in acceptable_junk_ents and not player_has_valuable_attr:
                        # If the only thing of value a player provides to a relation
                        # is a label and meta_attributes like date-seen, we don't
                        # want to add it.
                        # NOTE - we do this because doing a match_insert for a
                        # Relation causes issues if we match on $th isa label
                        # and get back literally all the entities of type label available.
                        _log.debug(f"Skipping USELESS player: {pformat(player.to_dict())}")
                        continue
                    tql += tql_temp
                    role_var = {role: q_var}
                    role_var_list.append(role_var)

            tql += f" insert ${thing.label}("
            for role_var in role_var_list:
                for role, var in role_var.items():
                    tql += f'{role}: ${var}, '
            tql = tql.rstrip(", ")
            tql += f') isa {thing.label};'

        else:
            tql = (
                f"match $empty-ent isa empty-ent; "
                f"insert ${thing.label}(related:$empty-ent) isa {thing.label};"
            )

        if thing.has:
            for attr in thing.has:
                fmt_val = self.format_value_query(attr.value)

                tql += f' ${thing.label} has {attr.label} {fmt_val};'

        return tql

    def get_query_or_mod(
        self,
        thing_var: str = '',
        or_mod: Dict = {},
        thing_counter: Optional[int] = 0,
    ):
        """
        Generates query string to add to get_query_from_thing() that allows for
        adding an 'or' factor to your search.

        :param thing_var: The variable we're attaching the or_mod to
        :param or_mod: contains label to 'or' on, action keyword, and values to compare
            format: {
                'label': 'hunt-name',
                'action': 'contains',
                'values': ['censys', 'shodan'],
            }
        """
        _log = self.logger
        tql = ''
        if not 'label' in or_mod or not or_mod['label']:
            _log.debug(f"generating or mod requires a label to focus on")
            return tql
        if not 'action' in or_mod or not or_mod['action']:
            _log.debug(f"generating or mod requires an action keyword")
            return tql
        if not 'values' in or_mod or not or_mod['values']:
            _log.debug(f"generating or mod requires a value")
            return tql

        label = or_mod['label']
        action = or_mod['action']
        if not isinstance(or_mod['values'], list):
            values = [or_mod['values']]
        else:
            values = or_mod['values']

        # define the label we want to or-pivot on
        tql += f" {thing_var} has {label} $ormod_{label}_{thing_counter};"
        for value in values:
            fmt_val = self.format_value_query(value)
            tql += f" {{ $ormod_{label}_{thing_counter} {action} {fmt_val}; }} or"
        tql = tql.rstrip(' or')
        tql += ';'
        return tql

    def get_query_sort_mod(
        self,
        thing_var: str = '',
        sort_mod: Dict = {},
        limit_get: bool = False,
        thing_counter: Optional[int] = 0,
    ):
        """
        Generates query string to add to get_query_from_thing() that allows for
        adding an 'or' factor to your search.

        :param thing_var: The variable we're attaching the sort_mod to
        :param sort_mod: contains label to sort on, sort method, offset, and limit
            format: {
                'label': 'hunt-name',
                'sort_method': 'asc',
                'offset': 0,
                'limit': 10,
            }
            Note: sort method defaults to 'asc', offset and limit are optional
        """
        _log = self.logger

        '''
        joshua — Today at 3:15 PM
        we unfortunately don't have support for sorting by internal ID, because
        if you include attributes, do you sort them by value or by IID?
        needs a different construct
        @TheDr1ver i'd recommend enumerating the items you want to sort with
        their own long attribute
        for the time being

        TheDr1ver — Today at 4:56 PM
        So basically assign a unique long to every entity and relation in the db?
        I guess I could do that if I figured out how to generate a long by using
        a UUID seed or something. I was kinda hoping there was just some way to
        just make sure that:

        match
            $ip isa ip;
            offset 0;
            limit 1;


        returned the exact same ip every time instead of seemingly
        random selections.
        '''

        tql = ''

        if not 'label' in sort_mod or not sort_mod['label']:
            label = ''
        else:
            label = sort_mod['label']
        if not 'sort_method' in sort_mod:
            sort_method = 'asc'
        else:
            sort_method = sort_mod['sort_method']
        if not 'offset' in sort_mod:
            offset = None
        else:
            offset = sort_mod['offset']
        if not 'limit' in sort_mod:
            limit = None
        else:
            limit = sort_mod['limit']



        if label:
            sort_var = f"$sortmod_{label}_{thing_counter}"
            tql += f" {thing_var} has {label} {sort_var};"
        if limit_get:
            tql += f" get {thing_var}"
        if label:
            tql += f", {sort_var}; sort {sort_var} {sort_method};"
        else:
            tql += ';'
        if not offset is None:
            tql += f" offset {offset};"
        if not limit is None:
            tql += f" limit {limit};"

        return tql

    def get_query_from_thing(
        self,
        thing: Thing=None,
        thing_counter: int = 0,
        limit_get: Optional[bool] = True,
        or_mod: Optional[Dict] = {},
        sort_mod: Optional[Dict] = {},
    ):
        """
        Given a Thing object (Attribute, Entity, Relation), use its properties to
        craft a proper TypeDB query.

        :param thing: Thing object for building the query
        :param thing_counter: Used for keeping track of sub-objects when processing
            things like relations
        :param limit_get: [DEPRECATED - Latest version of TypeDB REQUIRES a trailing GET]
            Set this to True if you only want to return the top-level
            object you're feeding the query builder.
        :param or_mod: If set, generates 'or' text disjunction patterns.
            format: {
                'label': 'hunt-name',
                'action': 'contains',
                'values': ['censys', 'shodan'],
            }
        :param sort_mod: If set, sorts the results based on sort_mod params:
            format: {
                'label': 'hunt-name',
                'sort_method': 'asc',
                'offset': 0,
                'limit': 10,
            }

        """

        _log = self.logger
        tql = ''

        ############################################################################
        #### DON'T FUCK WITH THE THING COUNTERS! IF YOU'RE BACK HERE IT'S
        #### SOMETHING ELSE! THIS FUNCTION IS GOOD! IT'S A YOU-PROBLEM! GO AWAY!
        ############################################################################
        # If no label is set, treat it as a generic thing
        if not thing.label:
            thing._label = 'thing'
        # If there's an iid, look no further - we know what we want
        if thing.iid:
            iid_trunc = thing.iid[-5:]
            tql = f' ${thing.label}_{iid_trunc} iid {thing.iid}; get ${thing.label}_{iid_trunc};'
            return tql
        # Otherwise, start building the query
        if not hasattr(thing, 'counter'):
            thing.counter = thing_counter
        # If this thing has a key, that's all we need to search for it
        if thing.label in self.thing_keys:
            if hasattr(thing, 'keyattr') and thing.keyattr:
                if hasattr(thing, 'has'):
                    for attr in thing.has:
                        if attr.label == thing.keyattr:
                            # returns an explicit thing based on keyattr value
                            fmt_val = self.format_value_query(attr.value)
                            if fmt_val:
                                tql = (
                                    f' ${thing.label}_{thing.counter} isa {thing.label},'
                                    f' has {attr.label} ${attr.label}_{thing.counter};'
                                    f' ${attr.label}_{thing.counter} = {fmt_val};'
                                )
                            else:
                                tql = (
                                    f' ${thing.label}_{thing.counter} isa {thing.label},'
                                    f' has {attr.label} ${attr.label}_{thing.counter};'
                                )
                            if limit_get:
                                tql += f" get ${thing.label}_{thing.counter};"
            if not tql:
                # The thing we received doesn't have the keyattr prop set/populated
                # so we'll search for the thing generically.
                keyattr = self.thing_keys[thing.label]
                tql = (
                    f' ${thing.label}_{thing.counter} isa {thing.label},'
                    f' has {keyattr} ${keyattr}_{thing.counter};'
                )
                # Commenting this out because if we don't know the keyattr value
                # and we return the tql without one, we're just looking for
                # $thing isa thing, has thing-key $thing-key_0; get $thing;
                # And that's pretty much useless.

                # So like.. when we're looking for hunts based on criteria that
                # are not hunt-names, this was ignoring all the criteria (like
                # hunt-active=True), which is kinda important.
                '''
                thing_var = f"${thing.label}_{thing.counter}"

                if or_mod:
                    tql += self.get_query_or_mod(
                        thing_var = thing_var,
                        or_mod=or_mod,
                        thing_counter=thing.counter,
                    )

                if sort_mod:
                    tql += self.get_query_sort_mod(
                        thing_var = thing_var,
                        sort_mod = sort_mod,
                        limit_get = limit_get,
                        thing_counter = thing.counter
                    )

                # if sort_mod is set, limit_get is handled there.
                elif limit_get:
                    tql += f" get {thing_var};"
                '''
            else:
                # If we got tql in the fist section it's because we have a valid
                # keyattr and we can return the tql here before processing further.
                return tql

        if hasattr(thing, 'players'):
            if not thing.players:
                tql = f' ${thing.label}_{thing.counter} isa {thing.label}'
            else:
                tql = " "
                role_dict_list = []
                for role, players in thing.players.items():
                    for player in players:
                        if not hasattr(player, 'counter'):
                            player.counter = thing.counter
                        tql += self.get_query_from_thing(player)
                        if player.iid:
                            playervar = f"${player.label}_{player.iid[-5:]}"
                        else:
                            playervar = f"${player.label}_{thing.counter}"
                        role_dict = {role: playervar}
                        role_dict_list.append(role_dict)
                        thing.counter += 1
                if role_dict_list:
                    tql += f" ${thing.label}_{thing.counter}("
                    first=True
                    for rd in role_dict_list:
                        for role, player_var in rd.items():
                            if not first:
                                tql += f", {role}: {player_var}"
                                continue
                            tql += f"{role}: {player_var}"
                            first=False
                    tql += f") isa {thing.label}"
        else:
            tql = f' ${thing.label}_{thing.counter} isa {thing.label}'
        if not hasattr(thing, 'has'):
            tql += ";"
            if hasattr(thing, 'value') and thing.value is not None:
                fmt_val = self.format_value_query(thing.value)
                tql += f' ${thing.label}_{thing.counter}={fmt_val}; get;'
            return tql
        if len(thing.has) > 0:
            first = True
            c = thing.counter
            attr_vals = []
            attr_labels = []
            first = True
            for attr in thing.has:
                if not attr.label:
                    attr.label = "attribute"
                if attr.label in attr_labels:
                    continue
                if first:
                    tql += f', has {attr.label} ${attr.label}_{c}'
                    first = False
                else:
                    tql += f'; ${thing.label}_{thing.counter} has {attr.label} ${attr.label}_{c}'
                if attr.value is None:
                    attr_labels.append(attr.label)
                else:
                    s = f'; ${attr.label}_{c} = {self.format_value_query(attr.value)}'
                    tql += s
                c += 1
            tql += ";"
            for av in attr_vals:
                tql += av
        else:
            tql += ";"

        thing_var = f"${thing.label}_{thing.counter}"
        if or_mod:
            tql += self.get_query_or_mod(
                thing_var = thing_var,
                or_mod=or_mod,
                thing_counter=thing.counter,
            )

        if sort_mod:
            tql += self.get_query_sort_mod(
                thing_var = thing_var,
                sort_mod = sort_mod,
                limit_get = limit_get,
                thing_counter = thing.counter
            )

        # if sort_mod is set, limit_get is handled there.
        elif limit_get:
            tql += f" get {thing_var};"



        return tql

    def get_thing_keys(
        self,
    ):
        _log = self.logger
        _log.debug(f"Obtaining things with keys from schema...")
        thing_keys = {}

        tx = self.check_tx(tx=self.tx)
        concepts = tx.concepts
        try:
            ents = concepts.get_entity_type('entity').resolve()
        except TypeDBException:
            tx = self.check_tx()
            concepts = tx.concepts
            ents = concepts.get_entity_type('entity').resolve()

        ents_subs = ents.get_subtypes(tx)

        for ent in ents_subs:
            label = ent.get_label().name
            ent_keys = ent.get_owns(
                tx,
                value_type=None, 
                annotations={Annotation.key()} # updated v 2.18.0
            )
            key_label = False
            for ek in ent_keys:
                key_label = ek.get_label().name
            if key_label:
                thing_keys[label] = key_label

        try:
            rels = concepts.get_relation_type('relation').resolve()
        except TypeDBException:
            tx = self.check_tx()
            concepts = tx.concepts
            rels = concepts.get_relation_type('relation').resolve()

        rels_subs = rels.get_subtypes(tx)
        for rel in rels_subs:
            label = rel.get_label().name
            rel_keys = rel.get_owns(
                tx,
                value_type=None,
                annotations={Annotation.key()}
            )
            key_label = False
            for rk in rel_keys:
                key_label = rk.get_label().name
            if key_label:
                thing_keys[label] = key_label

        self.thing_keys = thing_keys
        return self.thing_keys

    def ledid_set(
        self,
        thing: Union[Entity, Relation] = None,
    ):
        """
        Given an Entity or Relation, loop through their 'has' attributes looking
        for an 'ledid' Attribute. Once found, set that as the Thing's ledid property.
        """
        _log = self.logger
        if not isinstance(thing, (Entity, Relation)):
            _log.error(
                f"Cannot set ledid for anything other than Entities "
                f"or Relations!"
            )
            return thing
        for attr in thing.has:
            if attr.label == 'ledid':
                thing.ledid = attr
        return thing

    def ledid_del(
        self,
        thing: Union[Entity, Relation] = None,
    ):
        """
        Removes ledid property from Entities and Relations, and removes ledid
        Attribute from Entity and Relation.has[]. Right now, only used when
        converting a TypeDB concept into a proper Thing data class.
        """
        _log = self.logger
        if not isinstance(thing, (Entity, Relation)):
            return thing
        del thing.ledid
        return thing

    def load_schema(
        self,
        db_server: Optional[str] = "",
        db_name: Optional[str] = "",
        thing: Optional[Thing] = None,
    ):
        _log = self.logger

        db_server = db_server or self.db_server
        db_name = db_name or self.db_name

        schema = {
            "Attributes": [],
            "Entities": [],
            "Relations": [],
            "Roles": [],
        }

        exists = self.check_db(db_name)
        if not exists:
            _log.error(f"Database {db_name} does not exist!")
            return schema

        if thing:
            _log.debug(f"Loading schema for specific thing")
            copy_thing = copy.deepcopy(thing)
        else:
            _log.debug(f"Attempting to load schema as objects...")
        session = self.create_session(
            session_type=SessionType.DATA,
            db_name=db_name,
            save_session=False,
        )
        tx = self.create_transaction(
            session=session,
            save_tx=False
        )

        concepts = tx.concepts

        # If thing passed, only update schema for this thing
        if thing:
            # ! thing_type = concepts.get_thing_type(thing.label)
            if isinstance(thing, Attribute):
                thing_type = concepts.get_attribute_type(thing.label).resolve()
            elif isinstance(thing, Entity):
                thing_type = concepts.get_entity_type(thing.label).resolve()
            elif isinstance(thing, Relation):
                thing_type = concepts.get_relation_type(thing.label).resolve()
            remote_thing = thing_type
            copy_thing.abstract = remote_thing.is_abstract(tx)
            if isinstance(thing, Attribute):
                _log.debug(f"Schema loaded for thing: {copy_thing.to_dict()}")
                tx.close()
                session.close()
                return copy_thing

            # Only thing left are Ents or Relations, both have 'owns' and 'keys'
            thing_owns = remote_thing.get_owns(
                tx, value_type=None, annotations={}
            )
            thing_keys = remote_thing.get_owns(
                tx, value_type=None, annotations={Annotation.key()}
            )
            for to in thing_owns:
                copy_thing.owns.append(to.get_label().name)
            for tk in thing_keys:
                keyname = tk.get_label().name
                for attr_label in thing.owns:
                    if keyname == attr_label:
                        copy_thing.keyattr=keyname

            if isinstance(thing, Entity):
                ent_plays = remote_thing.get_plays(tx)
                for ep in ent_plays:
                    epr = ep.get_label().scoped_name()
                    copy_thing.plays.append(epr)
                    _log.debug(f"Schema loaded for thing: {thing.to_dict()}")
                    tx.close()
                    session.close()
                    return copy_thing
            if isinstance(thing, Relation):
                rel_roles = remote_thing.get_relates(tx)
                for rr in rel_roles:
                    copy_thing.roles.append(rr.get_label().scoped_name())
                _log.debug(f"Schema loaded for thing: {copy_thing.to_dict()}")
                tx.close()
                session.close()
                return copy_thing

        attrs = concepts.get_attribute_type('attribute')
        attrs_subs = attrs.get_subtypes(tx)

        ents = concepts.get_entity_type('entity').resolve()
        ents_subs = ents.get_subtypes(tx)

        rels = concepts.get_relation_type('relation').resolve()
        rels_subs = rels.get_subtypes(tx)

        for attr in attrs_subs:
            label = attr.get_label().name
            abstract = attr.is_abstract(tx)
            attr_obj = Attribute(
                label=label,
                abstract = abstract,
            )
            schema['Attributes'].append(attr_obj)

        for ent in ents_subs:
            label = ent.get_label().name
            abstract = ent.is_abstract(tx)
            ent_obj = self.ledid_del(Entity(
                label=label,
                abstract=abstract,
            ))

            ent_owns = ent.get_owns(
                tx, value_type=None, annotations={}
            )
            ent_keys = ent.get_owns(
                tx, value_type=None, annotations={Annotation.key()}
            )
            ent_plays = ent.get_plays(tx)

            for eo in ent_owns:
                # eoa = Attribute(label = eo.get_label().name)
                ent_obj.owns.append(eo.get_label().name)
            for ek in ent_keys:
                keyname = ek.get_label().name
                for attr_label in ent_obj.owns:
                    if keyname == attr_label:
                        ent_obj.keyattr = keyname
            for ep in ent_plays:
                epr = Role(
                    label = ep.get_label().name,
                    scope = ep.get_label().scope,
                    scoped_name = ep.get_label().scoped_name()
                )
                ent_obj.plays.append(epr)

            schema['Entities'].append(ent_obj)

        for rel in rels_subs:
            label = rel.get_label().name
            abstract = rel.is_abstract(tx)
            rel_obj = self.ledid_del(Relation(
                label=label,
                abstract=abstract,
            ))

            rel_owns = rel.get_owns(
                tx, value_type=None, annotations={}
            )
            rel_keys = rel.get_owns(
                tx, value_type=None, annotations={Annotation.key()}
            )
            rel_roles = rel.get_relates(tx)

            for ro in rel_owns:
                rel_obj.owns.append(ro.get_label().name)
            for rk in rel_keys:
                keyname = rk.get_label().name
                for attr in rel_obj.owns:
                    if keyname == attr:
                        rel_obj.keyattr = keyname
            for rr in rel_roles:
                rel_obj.roles.append(rr.get_label().scoped_name())

                rr_label = rr.get_label().name
                rr_abstract = rr.is_abstract(tx)
                rr_scope = rr.get_label().scope
                rr_scoped_name = rr.get_label().scoped_name()
                role_obj = Role(
                    label = rr_label,
                    abstract = rr_abstract,
                    scope = rr_scope,
                    scoped_name = rr_scoped_name
                )
                if role_obj not in schema['Roles']:
                    schema['Roles'].append(role_obj)

            schema['Relations'].append(rel_obj)

        tx.close()
        session.close()
        if self.tx:
            self.tx.close()

        _log.debug(f"Finished loading schema:")
        for k, v in schema.items():
            _log.debug(f"{k}: {len(v)}")

        self.schema = schema
        return schema

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

    def populate_thing_from_schema(self, thing):
        _log = self.logger
        if not self.schema:
            self.load_schema()
        schema = self.schema
        if isinstance(thing, Attribute):
            for sch_obj in schema['Attributes']:
                if sch_obj.label == thing.label:
                    thing.update(**sch_obj)
        elif isinstance(thing, Entity):
            for sch_obj in schema['Entities']:
                if sch_obj.label == thing.label:
                    thing.update(**sch_obj)
        elif isinstance(thing, Relation):
            for sch_obj in schema['Relations']:
                if sch_obj.label == thing.label:
                    thing.update(**sch_obj)
        elif isinstance(thing, Role):
            for sch_obj in schema['Roles']:
                if sch_obj.label == thing.label:
                    thing.update(**sch_obj)
        else:
            _log.warning(f"Unable to find schema type {type(thing)}!")

        return thing

    def process_query_answers(
        self,
        answers: object = None,
        myquery: Query = None,
        tx: object = None,
        return_things = False,
    ):
        _log = self.logger
        myquery.answers = []
        target_thing = myquery.target_thing
        temp_answers = []
        unique_iids = []
        tx_type = tx.transaction_type

        # Deletions just commit and go
        if myquery.qtype in ["delete", "match_delete"]:
            myquery.answers = answers
            tx.commit()
            if self.tx:
                self.tx.close()
            return myquery

        # Everything else, we process.
        num_answers = 0
        if return_things:
            if not answers:
                return myquery
            # @ TODO - This is gonna need to be addressed at some point I'm sure.
            # ! print(type(answers))
            # ! if isinstance(answers, QueryFuture):
            # !     myquery.answers = answers.get()
            # !     return myquery
            for answer in answers:
                num_answers += 1
                if isinstance(answer, ConceptMap):
                    concepts = answer.concepts()
                    for concept in concepts:
                        thing = self.concept_to_thing(
                            concept,
                            tx,
                            search_mode=myquery.search_mode,
                        )

                        if isinstance(thing, Attribute):
                            if thing.value and isinstance(thing.value, str):
                                new_val = thing.value.replace("\\\"", "\"")
                                iid = thing.iid
                                thing = Attribute(
                                    iid=iid, label=thing.label, value=new_val
                                )

                        if tx_type == TransactionType.WRITE:
                            if isinstance(thing, type(target_thing)):
                                thing.iid = None
                                temp_answers.append(thing)
                        elif tx_type == TransactionType.READ:
                            if thing.iid not in unique_iids:
                                unique_iids.append(thing.iid)
                                myquery.answers.append(thing)
            if num_answers == 0:
                _log.debug(f"NO ANSWERS WERE PROCESSED!")

        # Commit any writes
        if tx_type == TransactionType.WRITE:
            tx.commit()
            _log.debug(f"Committed write!")
            if self.tx:
                self.tx.close()
            if not return_things:
                myquery.answers = True
                return myquery
            # Need to explicitly look for meta attributes if they're a keyattr
            confirmations = self.find_things(
                things = temp_answers,
                limit_get=True,
                search_mode='no_backtrace',
            )
            _log.debug(f"Confirmed written: {confirmations}")
            myquery.answers = confirmations
        return myquery

    def purge_abandoned_attributes(
        self,
        db_name: Optional[str] = "",
    ):
        _log = self.logger

        if not db_name:
            tx = self.create_transaction(
                tx_type = TransactionType.WRITE,
                save_tx=False,
            )
        else:
            tx = self.create_transaction(
                tx_type = TransactionType.WRITE,
                save_tx=False,
                db_name=db_name,
            )

        s = (
            "match $attr isa attribute; not {$x has $attr;};"
            " delete $attr isa attribute;"
        )
        myquery = Query(
            string = s,
            qtype = 'delete',
        )

        _log.info(f"Purging abandoned attributes...")
        answers = self.db_query(myquery, tx, save_tx=False)
        try:
            self.process_query_answers(
                answers, myquery, tx, return_things=False
            )
        except TypeDBException:
            _log.error(f"Transaction closed - reopening and trying again")
            tx = self.check_tx(tx=tx)
            answers = self.db_query(myquery, tx, save_tx=False)
            self.process_query_answers(
                answers, myquery, tx, return_things=False
            )
        return True

    def purge_abandoned_entities(
        self,
        db_name: Optional[str] = "",
        entity_type: Optional[str] = 'entity',
    ):
        """
        Deletes all entities that don't have a relation associated with them.

        Keep in mind, there's a high likelihood that there are some entities in
        a given database that might not be attached to a Relation that you still
        want to keep! As such, you'll probably want to modify this to target a
        specific entity to purge instead of all entities not attached to relations
        across the entire DB.

        NOTE: I only wrote this because I'd just finished writing purge_abandoned_attributes
        and I thought I might need this some day. I'm pretty sure this should never
        be needed in a prod environment, only when cleaning up a database where
        the schema keeps changing.
        """
        _log = self.logger

        if not db_name:
            tx = self.create_transaction(
                tx_type = TransactionType.WRITE,
                save_tx=False,
            )
        else:
            tx = self.create_transaction(
                tx_type = TransactionType.WRITE,
                save_tx=False,
                db_name=db_name,
            )

        s = (
            f"match $ent isa {entity_type};"
            " not {$rel($ent) isa relation;};"
            f" delete $ent isa {entity_type};"
        )
        myquery = Query(
            string = s,
            qtype = 'delete',
        )

        _log.info(f"Purging abandoned '{entity_type}' entities...")
        answers = self.db_query(myquery, tx, save_tx=False)
        try:
            self.process_query_answers(
                answers, myquery, tx, return_things=False
            )
        except TypeDBException:
            _log.error(f"Transaction closed - reopening and trying again")
            tx = self.check_tx(tx=tx)
            answers = self.db_query(myquery, tx, save_tx=False)
            self.process_query_answers(
                answers, myquery, tx, return_things=False
            )
        return True

    def raw_query(
        self,
        query: Query = None,
        db_name: Optional[str] = '',
        tx: Optional[object] = None,
    ):
        _log = self.logger
        if not db_name:
            db_name = self.db_name
        if not tx:
            tx = self.create_transaction(db_name=db_name)
        answers = self.db_query(query, tx=tx)
        response_query = self.process_query_answers(answers, query, tx, return_things=True)
        final_answers = response_query.answers
        return final_answers

    def replace_attribute(
        self,
        thing: Thing = None,
        new_attr: Attribute = None,
        iid: Optional[str] = "",
    ):
        """Replace all new_attr.label attributes Thing has with new_attr
        Given a Thing that has new_attr.label Attribute types attached to it,
            replace those attributes with new_attr instead.
        :param thing: Entity or Relation to modify
        :param new_attr: New attribute to attach to Entity or Relation that
            also dictates which existing attribute types/labels to remove.
        :param iid: If specified, only replaces the Attribute corresponding
            to this particular iid.

        :returns: Updated Thing object
        """
        _log = self.logger
        label = new_attr.label
        safe_copy = copy.deepcopy(thing)

        # Remove old attributes we want to replace
        for attr in safe_copy.has:
            if iid and attr.iid!=iid:
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

    def require_date_seen(
        self,
        thing: Union[Entity, Relation] = None,
    ):
        date_seen = False
        time_labels = [
            'date-seen',
            'first-seen',
            'last-seen'
        ]

        # Collect all date Attributes, and make sure their values
        # are all datetime objects
        for attr in thing.has:
            if attr.label == 'date-seen':
                date_seen = True

        # If no date-seen objects exist, make sure to add at least one
        if not date_seen:
            now = datetime.now(timezone.utc)
            now_attr = Attribute(label='date-seen', value=now)
            thing = self.attach_attribute(thing, now_attr, return_thing=True)

        return thing

    def super_update_first_last_seen(self):
        _log = self.logger
        _log.debug(f"Getting all entities and relations!")

        dateseen = Attribute(label="date-seen", value=None)
        blank_ent = self.ledid_del(Entity(label="entity", has=[dateseen]))
        blank_rel = self.ledid_del(Relation(label="relation", has=[dateseen]))
        ents = self.find_things(things=blank_ent, limit_get=True, search_mode='lite', include_meta_attrs=True)
        rels = self.find_things(things=blank_rel, limit_get=True, search_mode='lite', include_meta_attrs=True)
        all_ents_rels = ents + rels

        _log.debug(f"Fouund {len(all_ents_rels)} ents and rels!")

        for obj in all_ents_rels:
            self.update_first_last_seen(obj)
        return True

    def update_first_last_seen(self, thing):
        _log = self.logger
        date_seen_attrs = []
        first_seen = 0
        last_seen = 0
        existing_first_seen = None
        existing_last_seen = None
        true_first_seen = None
        true_last_seen = None

        for attr in thing.has:
            if attr.label == 'date-seen':
                date_seen_attrs.append(attr)
            if attr.label == 'first-seen':
                fs_attr = Attribute(iid=attr.iid, label=attr.label, value=format_date(attr.value))
                ts = int(format_date(attr.value).timestamp())
                if ts <= first_seen or first_seen == 0:
                    first_seen = ts
                    existing_first_seen = fs_attr
            if attr.label == 'last-seen':
                ls_attr = Attribute(iid=attr.iid, label=attr.label, value=format_date(attr.value))
                ts = int(format_date(attr.value).timestamp())
                if ts >= last_seen:
                    last_seen = ts
                    existing_last_seen = ls_attr

        # Update first/last
        for attr in date_seen_attrs:
            ts = int(format_date(attr.value).timestamp())
            if ts <= first_seen or first_seen == 0:
                first_seen = ts
                true_first_seen = Attribute(label='first-seen', value=format_date(attr.value))
            if ts >= last_seen:
                last_seen = ts
                true_last_seen = Attribute(label='last-seen', value=format_date(attr.value))

        # Double-check to make sure we didn't screw something up
        # and ensure there's only one instance of first-seen and last-seen
        updated_thing = thing
        if not existing_first_seen:
            self.attach_attribute(updated_thing, true_first_seen)
        elif true_first_seen and true_first_seen.value < existing_first_seen.value:
            self.detach_attribute(thing, existing_first_seen)
            self.attach_attribute(updated_thing, true_first_seen)

        if not existing_last_seen:
            self.attach_attribute(updated_thing, true_last_seen)
        elif true_last_seen and true_last_seen.value > existing_last_seen.value:
            self.detach_attribute(thing, existing_last_seen)
            self.attach_attribute(updated_thing, true_last_seen)

        return True

    def update_last_seen(
        self,
        thing: Thing = None,
        old_last_seen: Attribute = None,
    ):
        # TODO - This might no longer be needed with require_date_seen()
        #       being the norm now...
        _log = self.logger
        dto = datetime.now(timezone.utc)
        date_seen = Attribute(label='date-seen', value=dto)
        new_last_seen = Attribute(label='last-seen', value=dto)
        _log.info(f"Adding new date-seen to hunt...")
        self.add_attribute(thing, date_seen)
        self.remove_attribute(thing, old_last_seen)
        self.add_attribute(thing, new_last_seen)
        thing = self.find_things(thing, limit_get=True, search_mode='lite')
        _log.info(f"Added!")
        return thing[0]

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
        # // blank_thing = copy.deepcopy(Relation(label='relation'))

        # Make sure we get the full details of the existing thing before comparing
        # NOTE - This doesn't work with no_backtrace, so don't bother trying
        # NOTE - So... This might work with no_backtrace and significantly speed
        # things up.
        if old_thing:
            old_thing = self.find_things(
                old_thing,
                limit_get=True,
                search_mode='no_backtrace'
            )[0]
            # By using merge() we're only adding new stuff from the new_thing,
            # rather than removing things that are missing.
            # Also worth noting, merge() has checks to make sure we don't replace
            # pre-existing 'first-seen', 'last-seen', 'ledid', 'confidence',
            # or 'date-discovered' (see merge() functions in data_classes.py)
            old_copy = copy.deepcopy(old_thing)
            new_thing = old_copy.merge(**new_thing)

        if not new_thing.iid:
            _log.warning(
                f"Cannot update thing without IID! Did you mean to "
                f"add_thing instead?"
            )
            return False

        blank_thing.iid = new_thing.iid
        if not old_thing:
            find_thing_res = self.find_things(
                blank_thing,
                limit_get=True,
                search_mode='lite'
            )
            if isinstance(find_thing_res, list) and find_thing_res:
                if len(find_thing_res) > 1:
                    _log.warning(
                        f"There were {len(find_thing_res)} things that matched!"
                    )
                    _log.warning(f"Using first thing: {find_thing_res[0]}")
                old_thing = self.find_things(
                    find_thing_res[0],
                    search_mode='no_backtrace'
                )[0]
            elif find_thing_res:
                old_thing = self.find_things(
                    find_thing_res,
                    search_mode='no_backtrace'
                )[0]
        if not old_thing:
            _log.error(
                f"Unable to find existing thing with IID {blank_thing.iid}."
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
                try:
                    self.attach_attribute(old_thing, attr, return_things=False)
                    updated = True
                except Exception as e:
                    _log.error(f"Could not attach {attr} to {old_thing}!\n{e}")
                    pass

        if 'add_players' in diff_results:
            if diff_results['add_players']:
                for role, players in diff_results['add_players'].items():
                    for player in players:
                        try:
                            self.attach_player(
                                old_thing, role, player, return_things=False
                            )
                            updated = True
                        except Exception as e:
                            _log.error(
                                f"Could not attach {player} to {old_thing} "
                                f"as {role}!\n{e}"
                            )
                            pass

        if not updated:
            _log.warning(
                f"Even though diff_results weren't equal we didn't apply"
                f"any updates... returning old_thing. diff_results: "
                f"{pformat(diff_results)}"
            )
            return old_thing

        # Get final updated thing
        try:
            newest_thing = self.find_things(
                blank_thing,
                search_mode='no_backtrace',
                limit_get=True
            )[0]
            _log.debug(f"updated_thing: {newest_thing}")
        except IndexError:
            _log.error(f"Nothing found - something went horribly wrong!")
            _log.error(f"search_thing: {blank_thing}")
            raise

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
                                newest_thing = self.find_things(
                                    blank_thing,
                                    search_mode='no_backtrace',
                                    limit_get=True
                                )[0]
        if return_things:
            return newest_thing
        else:
            return True

    def write_tql_file(
        self,
        file: str = 'schema.tql',
        is_schema: Optional[bool] = True,
        client: Optional[TypeDB.core_driver] = None,
        db_name: Optional[str] = '',
        options: Optional[TypeDBOptions] = None,
    ):
        """
        Writes schema file to database.

        :param is_schema: True if writing a SCHEMA. False if writing a RULE.
        """
        _log = self.logger
        client = client or self.client
        db_name = db_name or self.db_name

        if is_schema:
            session_type = SessionType.SCHEMA
        else:
            session_type = SessionType.DATA

        db_exists = self.check_db(db_name)
        if not db_exists:
            _log.error(
                f"Database {db_name} does not exist. Cannot write schema!"
            )
            return False

        tql = ""
        with open(file, 'r') as f:
            for line in f.readlines():
                tql+=line
        _log.info(f"Writing TQL file {file}...")

        with client.session(db_name, session_type) as session:
            with session.transaction(TransactionType.WRITE) as tx:
                try:
                    tx.query.define(tql)
                    tx.commit()

                except Exception:
                    _log.error("Exception writing schema!", exc_info=True)
                    tx.close()
                    if self.tx:
                        self.tx.close()
                    session.close()
                    if self.session:
                        if self.session.is_open():
                            self.session.close()
                    raise
        if self.tx:
            self.tx.close()
        if self.session:
            if self.session.is_open():
                _log.debug(f"Session is open: {self.session.is_open()}")
                _log.debug(f"Closing 'apparently' open session {self.session}...")
                try:
                    self.session.close()
                except Exception as e:
                    _log.debug(f"Apparently it wasn't! {e}")
                # self.session.close()

        return True