# Installation

## Install Docker

https://docs.docker.com/engine/install/ubuntu/#installation-methods

### Ubuntu

```bash
# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add the repository to Apt sources:
echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

# Instlal packages
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Verify docker's working
sudo docker run hello-world

# (Optional) Configure user to run docker without sudo
sudo groupadd docker
sudo usermod -aG docker $USER

# Activate changes to groups
newgrp docker

# Verify
docker run hello-world
```

## Configure `gh` for authenticated cloning

```bash
# install github app (gh)
sudo apt install gh

# authenticate your GitHub account
gh auth login
```

## Install LEDHNTR-Docker

```bash
cd ~
git clone https://github.com/TheDr1ver/ledhntr-docker.git
```

## Modify Dockerfile to select plugins

`ledhntr-docker/docker/ledhntr.Dockerfile`

```Dockerfile
# Lines 41-47 install the following plugins by default:
RUN ledhntr install ./typedb_client
RUN ledhntr install ./jsonflats_client
RUN ledhntr install ./localfile_client
RUN ledhntr install ./json_collector
RUN ledhntr install ./shodan
RUN ledhntr install ./censys
RUN ledhntr install ./auto_hunter

# Of the above, only shodan and censys are optional. The rest are required for LEDMGMT to funciton properly.

# If you wish to add additional plugins just add a new line for each one following the same format (e.g. RUN ledhntr install ./zeta) and be sure add their associated configs to ledhntr.cfg in the next step.
```

## Modify `ledhntr.cfg`

```bash
cd ~/ledhntr-docker/docker
nano ledhntr.cfg
```

Add/Remove plugin configurations as needed. By default, shodan and censys are added, but in order for them to work properly you'll need to supply a valid key.

Additionally, this file is mounted into the docker instance as a volume, so any changes to it will be immediately reflected inside the docker instance (even though in most cases it will still require a restart of the ledmgmt container for the changes to take effect).

## Launch LEDHNTR-DOCKER

```bash
cd ~/ledhntr-docker/docker
# (optional) add the -d flag to run in background
docker compose up
```

## Access LEDMGMT interface

If you are running the docker image on a machine that has browser access, you can open the browser and point it to `http://127.0.0.1:5001`. If this is your first time activating the service, you will be asked to create an account before signing in.

If you are running the docker instance on a headless server, you'll need to set up port forwarding via the SSH Tunneling options described below.

# Using LEDMGMT

Once logged into the LEDMGMT interface, go to `Hunting -> Hunt Overview -> Add -> Add New Database`

Give the database a name.

Either an initial hunt or a collection of indicators are required to initialize the database.

Example:
```
Database Name: test_db
Hunt Name: 8080-banners
Hunt Service: Censys
Hunt Endpoint: censys_hosts_search
Hunt String: same_service(services.banner_hashes="sha256:c303855b4fb112d19763c8cf21731fb8a8a2b594cacebdfd4fcc265557d614f2" and services.port=8080) AND services.port:3389 AND NOT services.port:[8081 to *]
Confidence: Medium
Frequency: 24
```

Once created, you can click on the database to inspect its contents. Initially, only the hunt you created should be included in the database. It should automatically run when the background service launches every hour, or you can force it to manually populate via the `Run Hunts` button.
# MISC

## SSH Tunneling

In the event you're running all of this on an isolated VM and you wish to access the containerized resources from your host machine, you'll need to utilize SSH tunneling/port forwarding
### SSH CLI

```bash
# LEDMGMT interface
ssh <host running docker> -L 5001:127.0.0.1:5001
# TypeDB Client
ssh <host running docker> -L 1729:127.0.0.1:1729
# Both
ssh <host running docker> -L 5001:127.0.0.1:5001 -L 1729:127.0.0.1:1729
```

### SSH Config

```
Host myhost
	User myuser
	Hostname <your-host-ip>
	# IdentityFile ~/.ssh/my_priv_key
	# LEDMGMT interface
	LocalForward 5001 127.0.0.1:5001
	# TypeDB server
	LocalForward 1729 127.0.0.1:1729
```

### PuTTY

`Settings -> Connection -> SSH -> Tunnels`

```
# For accessing the LEDMGMT web interface
Source Port: 5001
Destination: 127.0.0.1:5001
Options: Local + Auto

# For accessing the TypeDB databases directly via TypeDB Studio or the LEDHNTR TypeDB Client
Source Port: 1729
Destination: 127.0.0.1:1729
Options: Local + Auto
```

## Accessing LEDHNTR-Docker via Local LEDHNTR Install

### Locally install LEDHNTR

See [INSTALL-Local](https://github.com/TheDr1ver/ledhntr-suite-public/INSTALL-Local.md) to
install LEDHNTR and your desired plugins on your local machine.

This makes it easier to develop notebooks that can easily interact with the
LEDHNTR-Docker instance, OR may be desirable if you're running something lean
that doesn't require a TypeDB database.

## Open Bash Terminal in docker instance

To attach to an already-running docker instance of ledmgmt, run:

```bash
docker exec -it docker-ledmgmt-1 bash
```

If ledmgmt is not already running for some reason, instead run:

```bash
docker run -ti ledmgmt bash
```
