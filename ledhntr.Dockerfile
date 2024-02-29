# using ubuntu LTS version
FROM ubuntu:22.04 AS builder-image

# avoid stuck build due to user prompt
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install --no-install-recommends -y python3.11 python3.11-dev python3.11-venv python3.11-distutils python3.11-gdbm python3.11-tk python3.11-lib2to3 python3-pip python3-wheel build-essential && \
	apt-get clean && rm -rf /var/lib/apt/lists/*

# Create the right user
RUN useradd --create-home leduser
USER leduser

# create and activate virtual environment
# using final folder name to avoid path issues with packages
RUN python3.11 -m venv /home/leduser/.ledhntr/.venv --prompt LEDHNTR
ENV PATH="/home/leduser/.ledhntr/.venv/bin:$PATH"

# install requirements
COPY requirements.txt .
RUN pip3 install --no-cache-dir wheel
RUN pip3 install --no-cache-dir -r requirements.txt
RUN mkdir -p /home/leduser/LEDHNTR && mkdir -p /home/leduser/ledhntr-plugins
COPY ./ledhntr/ /home/leduser/LEDHNTR/
COPY ./ledhntr.cfg /home/leduser/.ledhntr/
USER root
RUN chown -R leduser:leduser /home/leduser/LEDHNTR/
RUN chown -R leduser:leduser /home/leduser/.ledhntr/
USER leduser
WORKDIR /home/leduser/LEDHNTR

# RUN pip3 install --no-cache-dir .
# RUN pip3 install -e .
RUN pip3 install .
COPY ./ledhntr-plugins/ /home/leduser/ledhntr-plugins/
USER root
RUN chown -R leduser:leduser /home/leduser/ledhntr-plugins/
USER leduser
WORKDIR /home/leduser/ledhntr-plugins
USER leduser
# ; RUN ledhntr install ./typedb_client 
RUN ledhntr install ./jsonflats_client
RUN ledhntr install ./localfile_client
RUN ledhntr install ./json_collector
RUN ledhntr install ./shodan
RUN ledhntr install ./censys
# ; RUN ledhntr install ./auto_hunter

FROM ubuntu:22.04 AS runner-image

RUN apt-get update && apt-get install --no-install-recommends -y python3.11 python3.11-venv gunicorn supervisor && \
	apt-get clean && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home leduser
COPY --from=builder-image /home/leduser/.ledhntr /home/leduser/.ledhntr
COPY --from=builder-image /home/leduser/LEDHNTR /home/leduser/LEDHNTR
RUN chown -R leduser:leduser /home/leduser/

USER leduser
RUN mkdir /home/leduser/.ledhntr/logs
RUN mkdir /home/leduser/.ledhntr/data

# ; USER root
# ; RUN mkdir /opt/ledmgmt
# ; RUN mkdir /opt/ledmgmt/var
# ; RUN mkdir /opt/ledmgmt/var/log

# ; WORKDIR /opt/
# ; COPY ./ledmgmt/ /opt/ledmgmt/
# ; RUN chown -R leduser:leduser .

# ; USER leduser
# ; WORKDIR /opt/ledmgmt/ledmgmt/

# LEDMGMT interface
# ; EXPOSE 5001

# make sure all messages always reach console
# ; ENV PYTHONUNBUFFERED=1

# activate virtual environment
ENV VIRTUAL_ENV=/home/leduser/.ledhntr/.venv
ENV PATH="/home/leduser/.ledhntr/.venv/bin:$PATH"
ENV LEDHNTR_HOME="/home/leduser/.ledhntr"

# /dev/shm is mapped to shared memory and should be used for gunicorn heartbeat
# this will improve performance and avoid random freezes
# CMD ["gunicorn","-b", "0.0.0.0:5000", "-w", "4", "-k", "gevent", "--worker-tmp-dir", "/dev/shm", "app:app"]

# The autohunter script polls the databases hourly and updates hunts that need updating. 
# It also bootstraps the 'road' database if one doesn't exist already.
# ; CMD ["/opt/ledmgmt/run.sh", "python", "/opt/ledmgmt/supervisor_confs/autohunter.py", "&"]
# /opt/ledmgmt/run.sh python /opt/ledmgmt/supervisor_confs/autohunter.py
# ; CMD ["gunicorn","-c", "/opt/ledmgmt/ledmgmt/gunicorn-cfg.py", "--worker-tmp-dir", "/dev/shm", "run:app"]