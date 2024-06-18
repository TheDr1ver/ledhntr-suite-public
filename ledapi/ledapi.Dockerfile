# using python 3.12
FROM python:3.11.9-bullseye

# Install git
RUN apt update

RUN useradd --create-home leduser

WORKDIR /ledapi

RUN chown -R leduser:leduser /ledapi

# Switch to leduser
USER leduser
ENV PATH="/home/leduser/.local/bin:${PATH}"

# Copy and install dependencies
COPY --chown=leduser:leduser requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Clone ledhntr for install
RUN git clone https://github.com/TheDr1ver/ledhntr-suite-public.git /ledapi/ledhntr-suite-public
# Change branch for dev
WORKDIR /ledapi/ledhntr-suite-public
# Change ownership just to be sure
RUN chown -R leduser:leduser /ledapi/ledhntr-suite-public
# Explicitly check out the dev branch
RUN git checkout ledapi
# Install requirements
RUN pip install --no-cache-dir -r /ledapi/ledhntr-suite-public/requirements.txt
RUN pip install --no-cache-dir -r /ledapi/ledhntr-suite-public/ledhntr/requirements.txt
RUN pip install --no-cache-dir -e /ledapi/ledhntr-suite-public/ledhntr

# Install plugins
WORKDIR /ledapi/ledhntr-suite-public/ledhntr-plugins
RUN ledhntr install ./typedb_client/
RUN ledhntr install ./shodan/
RUN ledhntr install ./censys/

# Copy the configs to the .ledhntr directory
COPY --chown=leduser:leduser ledhntr.cfg /home/leduser/.ledhntr/

# Set the working dir to the application directory
WORKDIR /ledapi/ledhntr-suite-public/ledapi

# Run the server
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]