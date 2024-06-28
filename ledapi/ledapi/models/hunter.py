from pydantic import BaseModel, model_validator
from typing import Optional, Dict, List

from ledhntr.data_classes import(
    Attribute,
    Entity,
    Relation,
)

from ledapi.config import(
    led,
    _log,
    get_tdb,
    wqm,
)

#@##############################################################################
#@### Pydantic API models
#@##############################################################################
class HuntSubmission(BaseModel):
    plugin: str = None
    endpoint: str = None
    hunt_name: str = None
    query: str = None
    db_name: Optional[str] = None
    hunt_active: Optional[bool] = True
    frequency: Optional[float] = 24.0
    confidence: Optional[float] = 0.0
    add_as_enrichment: Optional[bool] = False
    """HuntSubmission Model for adding a hunt to the db

    - plugin, endpoint, hunt_name, and query are required
        plugin: the plugin you're going to use for your hunt
        endpoint: the API endpoint of the plugin you wish to submit your hunt to
        hunt_name: the unique name of your hunt
        query: The actual query you're sending to the endpoint
    - if db_name is not provided, defaults to 'scratchpad' which is reset weekly
    - hunt_active: defaults to True. As hunts are automatically run after they're
        submitted, if this is set to False it effectively runs once and never again.
    - frequency: is how often the hunt should run. Defaults to every 24 hrs.
    - confidence: 0=Unknown, 1=Low, 2=Medium, 3=High
    - add_as_enrichment:

    :raises ValueError: If anything is out of place
    """

    '''
    #* Make sure we have at least one value or label
    @model_validator(mode="before")
    @classmethod
    def check_values(cls, values):
        if not values.get('label') and not values.get('value'):
            raise ValueError('A "label" or "value" must be provided.')
        return values
    '''
    #~ Check for required fields
    @model_validator(mode="before")
    @classmethod
    def check_values(cls, values):
        required = ['plugin', 'hunt_name', 'endpoint', 'query']
        missing = [f for f in required if f not in values or values[f] is None]
        if missing:
            raise ValueError(f"Missing required fields: {missing}")
        return values

    #~ Validate plugin
    @model_validator(mode="before")
    @classmethod
    def check_plugin(cls, values):
        plugin_name = values.get('plugin')
        active_plugins = []
        for worker_name, details in wqm.conf.items():
            if details['_plugin_name'] == plugin_name:
                return values
            if details['_plugin_name'] not in active_plugins:
                active_plugins.append(details['_plugin_name'])
        raise ValueError(f"Invalid plugin name {plugin_name}. Must be one of {active_plugins}.")

    #~ Validate endpoint
    @model_validator(mode="before")
    @classmethod
    def check_endpoint(cls, values):
        endpoint = values.get('endpoint')
        plugin_name = values.get('plugin')
        valid_endpoints = []
        for worker_name, details in wqm.conf.items():
            if details['_plugin_name'] == plugin_name:
                plugin = details['_plugin']
                valid_endpoints = list(plugin.api_confs.keys())
                if endpoint in valid_endpoints:
                    return values
        raise ValueError(f"Invalid endpoint: {endpoint}. Must be one of {valid_endpoints}.")
    
    #~ Check that DB actually exists
    @model_validator(mode="before")
    @classmethod
    def check_db(cls, values):
        db_name = values.get('db_name')
        tdb = get_tdb()
        if db_name:
            all_dbs = tdb.get_all_dbs(readable=True)
            tdb.close_client()
            if db_name not in all_dbs:
                raise ValueError(f"Database {db_name} does not exist!")
        else:
            _log.debug(f"db_name not provided - defaulting to 'scratchpad'")
            values['db_name'] = "scratchpad"
        return values

    #~ Validate hunt-name
    @model_validator(mode="before")
    @classmethod
    def check_hunt_name(cls, values):
        hunt_name = values.get('hunt-name')
        db_name = values.get('db_name')

        tdb = get_tdb()
        tdb.db_name = db_name
        so = Entity(label='hunt', has=[Attribute(label='hunt-name', value=hunt_name)])
        rez = tdb.find_things(so, search_mode='lite')
        tdb.close_client()
        if rez:
            raise ValueError(f"Database {db_name} already has a hunt named {hunt_name}")
        return values

    #~Validate hunt query
    @model_validator(mode="before")
    @classmethod
    def check_hunt_query(cls, values):
        query = values.get('query')
        db_name = values.get('db_name')
        tdb = get_tdb()
        tdb.db_name = db_name
        so = Entity(label='hunt', has=[Attribute(label='hunt-string', value=query)])
        rez = tdb.find_things(so, search_mode='lite')
        tdb.close_client()
        if rez:
            raise ValueError(f"Database {db_name} already has a hunt with search value {query}")
        return values


