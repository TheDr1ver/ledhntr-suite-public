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
cd ~/LEDHNTR/ledhntr
pip install -r requirements.txt
pip install -e . # -e switch lets you apply changes on the fly without reinstalling
```

## Install Plugins

Example plugins to install:

```bash
ledhntr install --github ledhntr:typedb_client
ledhntr install --github ledhntr:json_collector
ledhntr install --github ledhntr:shodan
ledhntr install --github ledhntr:censys
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

**IMPORTANT** - `[typedb_client] -> db_server` this value of `127.0.0.1:1729` should work if you are using an LEDHNTR install on the same host that's running LEDHNTR-Docker, OR if you installed LEDHNTR on another host and used the SSH Tunneling configs discussed in this README.

# Test Runs

Assuming you are still running a terminal under which you activated your virtual environment (e.g. `source ~/.ledhntr/.venv/bin/activate` or `C:\Users\<user>\.ledhntr\.venv\Scripts\> activate.bat`) open an interactive Python prompt and run the following to test various functionalities:

### Test LEDHNTR TypeDB Connection

```python
from ledhntr import LEDHNTR
led = LEDHNTR()
tdb = led.load_plugin('typedb_client')
tdb.check_db('road')
# Should return True if connections are working and everything initialized properly
tdb.check_db('foo')
# Should return False unless you have created a database named 'foo'
```

### Test a Shodan 