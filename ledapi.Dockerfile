# using python 3.12
FROM python:3.11.9-bullseye

# Get ARGS
ARG PLUGINS

# Install git
RUN apt update

RUN useradd --create-home leduser

# Clone ledhntr for install
RUN git clone https://github.com/TheDr1ver/ledhntr-suite-public.git /ledhntr/

WORKDIR /ledhntr

RUN chown -R leduser:leduser /ledhntr

# Switch to leduser
USER leduser
ENV PATH="/home/leduser/.local/bin:${PATH}"
ENV PYTHONPATH="$PYTHONPATH:/ledhntr/ledapi:/home/leduser/.ledhntr/plugins"

WORKDIR /ledhntr

# Explicitly check out the dev branch - #! REMOVE THIS BEFORE MERGING WITH MAIN
RUN git checkout ledapi

# Install requirements
RUN pip install --no-cache-dir -r requirements.txt

# Install LEDHNTR
RUN pip install --no-cache-dir -e /ledhntr/ledhntr

# Install plugins
WORKDIR /ledhntr/ledhntr-plugins
RUN ledhntr install ./typedb_client/
RUN set -ex \
  && plugins=$(echo $PLUGINS | tr " " "\n") \
  && for plugin in $plugins; do \
       echo "Installing $plugin"; \
       ledhntr install ./$plugin; \
     done

# Copy the configs to the .ledhntr directory
COPY --chown=leduser:leduser ledhntr.cfg /home/leduser/.ledhntr/

# Set the working dir to the application directory
WORKDIR /ledhntr/ledapi

# Run the server
# CMD ["uvicorn", "ledapi.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
# Using this for dev work #! SWITCH BACK TO ABOVE BEFORE MERGING WITH MAIN
# @ I just want to leave the container running so I can get colored bash outputs
# @ in my logs while dev'ing. Normally I won't have bash in this container.
# @ uvicorn ledapi.main:app --host 0.0.0.0 --port 8000 --reload
CMD ["tail", "-f", "/dev/null"]
