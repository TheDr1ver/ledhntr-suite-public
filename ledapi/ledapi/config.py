from ledhntr import LEDHNTR
from ledhntr.data_classes import Attribute, Entity, Relation, Thing, Query

# Load LEDHNTR
led = LEDHNTR()
tdb = led.load_plugin('typedb_client')
_log = led.logger

# Set log level
_log.setLevel('DEBUG')

# Organize Schema so we don't have to do it again
led.all_labels = {
    'thing': [],
    'attribute': [],
    'entity': [],
    'relation': [],
}
for ttype in led.schema.keys():
    for thing in led.schema[ttype]:
        if thing['label'] not in led.all_labels:
            led.all_labels['thing'].append(thing['label'])
        if thing['type']=='attribute':
            led.all_labels['attribute'].append(thing['label'])
        elif thing['type']=='entity':
            led.all_labels['entity'].append(thing['label'])
        elif thing['type']=='relation':
            led.all_labels['relation'].append(thing['label'])