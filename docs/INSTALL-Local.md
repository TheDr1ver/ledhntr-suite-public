# LEDHNTR Local Install

## Python

In both Ubuntu and Windows instances, I'm assuming you're running **Python 3.11**
and have it aliased to `python3`. Other versions of Python may work (this was
written on 3.7, 3.9, 3.10, and 3.11 over time), but you may run into weird errors
if you use something other than 3.11.

## Ubuntu User Account

In Ubuntu it can make things simpler/more compartmentalized if you install LEDHNTR
under its own user, but it's perfectly okay to skip this first step if you don't
want another user account created.

```bash
# Setup LEDHNTR user
sudo adduser leduser # add leduser to own the project
sudo usermod -aG sudo leduser # optional if you want leduser to have sudo rights
sudo usermod -aG leduser <your_main_username> # if you want rights added to your account
newgrp leduser # refresh your groups list
# note if you want to access LEDHNTR as your primary user, you need to set the environment varible
export LEDHNTR_HOME="/home/leduser/.ledhntr"
# Add the above to your logon bash script if you wish to load it every time you get a new shell
sudo su - leduser # switch to the newly created account before running the rest
```

## Setup LEDHNTR directories + Virtual Environment

### Ubuntu

```bash
mkdir -p ~/.ledhntr/plugins
mkdir -p ~/.ledhntr/logs
mkdir -p ~/.ledhntr/data
python3 -m venv ~/.ledhntr/.venv --prompt LEDHNTR
source ~/.ledhntr/.venv/bin/activate
```

### Windows

```shell
C:\> cd C:\Users\<myuser>\
C:\Users\<myuser>\> dir .ledhntr
C:\Users\<myuser>\> cd .\.ledhntr\
C:\Users\<myuser>\.ledhntr\> python3 -m venv C:\Users\<myuser>\.ledhntr\.venv\ --prompt LEDHNTR
C:\Users\<myuser>\.ledhntr\> cd .\.venv\Scripts\
C:\Users\<myuser>\.ledhntr\.venv\Scripts\> activate.bat
```

## Install LEDHNTR

```bash
cd ~
git clone https://github.com/TheDr1ver/ledhntr-suite-public.git
cd ~/ledhntr-suite-public/ledhntr
pip install -r requirements.txt
pip install -e . # -e switch lets you apply changes on the fly without reinstalling
```

## Install Plugins

Example plugins to install:

```bash
ledhntr install --github ledhntr:json_collector
ledhntr install --github ledhntr:shodan
ledhntr install --github ledhntr:censys
# To upgrade plugins you MUST include the --upgrade flag
# You may also install local plugins by omitting the --github flag and
#     specifying the local directory
#     e.g. ledhntr install /home/leduser/ledhntr-suite-public/ledhntr-plugins/sample-plugin/
```

## Configure LEDHNTR

This is an example `~/.ledhntr/ledhntr.cfg` file. Additional configurations
examples can be found in each individual plugin's directory.:

```ini
[core]

# Default Logging settings
log_dir: logs
log_level: INFO
log_maxbytes: 150000
log_backup_count: 5
log_syntax: text

# Default plugin directory:
## Best to leave this alone on Windows
## Only change this if you want to use explicitly installed your plugins
## in a different directory.
# plugin_dir_list: ~/.ledhntr/plugins

[typedb_client]
# Number of threads per client
parallelisation=4

## Default name of the typedb database to interact with
db_name = test_db

## NOTE: in the top dir this is set to typedb:1729 for Docker purposes.
## If installing locally you'll probably want this set to localhost.
## Otherwise, if you have an external TypeDB server that you know is listening
## set this value to that IP/port combination.
db_server = 127.0.0.1:1729

[json_collector]
path = ./data/json_collector/api_results/
max_files = 3

[jsonflats_client]
path = ./data/jsonflats/
db_name = test_db

[censys]
base_url = https://search.censys.io/api/
key = <your_key>
secret = <your_secret>
ssl_verify=False
# Default threshold for re-running hunts
default_threshold = 24
# Rate limit - only call censys once every this many seconds
rate_limit = 2

[shodan]
base_url = https://api.shodan.io/
key = <your_key>
ssl_verify=False
default_threshold=24
rate_limit = 2
```

**IMPORTANT** - `[typedb_client] -> db_server` this value of `127.0.0.1:1729` should work if you are using an LEDHNTR install on the same host that's running LEDHNTR-Docker.

# Test Runs

Assuming you are still running a terminal under which you activated your virtual environment (e.g. `source ~/.ledhntr/.venv/bin/activate` or `C:\Users\<user>\.ledhntr\.venv\Scripts\> activate.bat`) open an interactive Python prompt and run the following to test various functionalities:

### Test a Shodan Search

```python
from ledhntr import LEDHNTR
led = LEDHNTR()
shodan = led.load_plugin('shodan')
api_conf = shodan.api_confs.get('hosts_search')
q = 'asn:AS44477 os:Unix product:vsftpd'
api_conf.params['query'] = q
res = shodan.search(api_conf=api_conf)
# res is a dictionary containing parsed Thing objects and raw API response
res['raw']['total'] # total shodan hits
from pprint import pprint
pprint(res['things'][0].to_dict()) # pretty-prints first parsed Thing object

# Write results to flat JSON file
filesys_client = led.load_plugin('localfile_client')
fc = filesys_client
fc.set_path(path="./data/local/", db_name='20240229_TEST')
fc.write_thing(res['things'][0])
fc.write_raw_json(res['raw'])
pprint(fc.list_dir(fc.full_path))

# Loop through Shodan results and pull details for each found IP
for thing in res['things']:
    if thing.label == 'ip' and thing.keyval:
        api_conf2 = shodan.api_confs.get('host_details')
        api_conf2.params['query'] = thing.keyval
        detail_res = shodan.search(api_conf2)
        fc.write_raw_json(detail_res['raw'], filename=f"{thing.keyval}-", append_date=True)
```

### Censys Get Up To 10 Pages of Results

```python
import copy
from ledhntr import LEDHNTR
led = LEDHNTR()
censys = led.load_plugin('censys')
# Set up your file storage
filesys_client = led.load_plugin('localfile_client')
fc = filesys_client
fc.set_path(path="./data/local/", db_name='20240229_TEST_CENSYS')
# Run your base Censys search
api_conf = censys.api_confs.get('search')
q = '(autonomous_system.asn="44477") and services.software.product=`vsFTPd`'
api_conf.params['q']=q
all_things = []
counter = 0
# Loop through a max of 10 pages of results
while counter < 10:
    res = censys.search(api_conf=api_conf)
    # Store all the parsed things that were found
    all_things.append(res['things'])
    # Write the results to disk
    fc.write_raw_json(res['raw'], filename=f"{counter}-", append_date=True)
    cursor = res['raw']['result'].get('links', {}).get('next')
    # If a cursor exists, grab the next page. Otherwise kill the loop
    if not cursor:
        break
    api_conf.params['cursor'] = cursor
    counter += 1
# Get each IP's individual details
for thing in all_things:
    if thing.label == 'ip' and thing.keyval:
        api_conf2 = copy.deepcopy(censys.api_confs.get('host_details'))
        api_conf2.params['q']=thing.keyval
        detail_res = censys.search(api_conf2)
        fc.write_raw_json(detail_res['raw'], filename=f"{thing.keyval}-", append_date=True)
```

### Read a dir full of rules and run ones that have reached the appropriate threshold

```python
import copy
from ledhntr import LEDHNTR
led = LEDHNTR()
# Load storage plugin
files = led.load_plugin('localfile_client')
# Load YAML plugin
yaml = led.load_plugin('yaml_client')
yaml.set_path('/opt/test/hunts') # Location of *.yaml files to load
yaml.load_hunts()
yaml.check_threshold() # Checks threshold timestamps to remove recently-run hunts
for hunt in yaml.hunts:
    failed_load = False
    try:
        plugin = led.load_plugin(hunt['plugin'])
    except Exception as e:
        led.logger.error(f"Could not load {hunt['plugin']} - {e}")
        failed_load = True
    if failed_load:
        continue
    # Build enrichment map
    if not hasattr(plugin, 'enrich_map') or not plugin.enrich_map:
        plugin._gen_enrich_map()
    # Set the output location based on the YAML's output field
    files.set_path(path=f"{hunt['output']}/", db_name=hunt['id'])
    # Load the plugin configs for the endpoint we're about to hit
    api_conf = copy.deepcopy(plugin.api_confs.get(hunt['endpoint']))
    api_conf.paginate=True
    # Set hunt parameters
    for k, v in hunt[hunt['endpoint']].items():
        api_conf.params[k]=v
    all_things = []
    res = plugin.search(api_conf=api_conf)
    for thing in res['things']:
        if thing not in all_things:
            all_things.append(thing)
    if not hasattr(plugin, 'chunk_results'):
        files.write_raw_json(res['raw_pages'], filename=f"{hunt['id']}-no_chunks-", append_date=True))
    else:
        chunks = plugin.chunk_results(res['raw_pages'], api_conf=api_conf)
        chunk_no = 1
        for chunk in chunks:
            files.write_raw_json(chunk, filename=f"{hunt['id']}-{chunk_no}_of_{len(chunks)}-", append_date=True)
            chunk_no+=1

    # Get each IP's individual details
    for thing in all_things:
        if thing.label == 'ip' and thing.keyval:
            api_conf2 = copy.deepcopy(
                plugin.api_confs.get(plugin.enrich_map['ip']['endpoints'][0])
            )
            api_conf2.params[api_conf2.param_query_key]=thing.keyval
            detail_res = plugin.search(api_conf2)
            files.write_raw_json(
                detail_res['raw'],
                filename=f"{hunt['id']}-{thing.keyval}-",
                append_date=True
            )

    # Update the last run time
    yaml.update_lastrun(hunts=[hunt])
```
