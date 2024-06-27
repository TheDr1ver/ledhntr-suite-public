# using python 3.12
FROM python:3.11.9-bullseye

# Get ARGS
ARGS PLUGINS

# Install git
RUN apt update

RUN useradd --create-home leduser

WORKDIR /ledhntr

RUN chown -R leduser:leduser /ledhntr

# Switch to leduser
USER leduser
ENV PATH="/home/leduser/.local/bin:${PATH}"
ENV PYTHONPATH="$PYTHONPATH:/ledhntr/ledapi:/home/leduser/.ledhntr/plugins"

# Copy and install dependencies
COPY --chown=leduser:leduser requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Clone ledhntr for install
RUN git clone https://github.com/TheDr1ver/ledhntr-suite-public.git /ledhntr/
WORKDIR /ledhntr
# Change ownership just to be sure
RUN chown -R leduser:leduser /ledhntr
# Explicitly check out the dev branch
RUN git checkout ledapi
# Install requirements
RUN pip install --no-cache-dir -r /ledhntr/requirements.txt
RUN pip install --no-cache-dir -r /ledhntr/ledhntr/requirements.txt
RUN pip install --no-cache-dir -e /ledhntr/ledhntr

# Install plugins
WORKDIR /ledhntr/ledhntr-plugins
RUN ledhntr install ./typedb_client/
RUN set -ex \
  && IFS=' ' read -r -a plugins <<< "$PLUGINS" \
  && for plugin in "${plugins[@]}"; do \
       echo "Installing $plugin"; \
       # Replace with actual installation command for the plugin, e.g. pip install
       ledhntr install ./$plugin; \
     done

# Copy the configs to the .ledhntr directory
COPY --chown=leduser:leduser ledhntr.cfg /home/leduser/.ledhntr/

# Set the working dir to the application directory
WORKDIR /ledhntr/ledapi

# Run the server
CMD ["uvicorn", "ledapi.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]