# using python 3.12
FROM python:3.11.9-bullseye

# Install git
RUN apt update

RUN useradd --create-home leduser

WORKDIR /ledapi

RUN chown -R leduser:leduser /ledapi

USER leduser

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Clone ledhntr for install
RUN git clone https://github.com/TheDr1ver/ledhntr-suite-public /ledapi/ledhntr-suite-public
RUN pip install --no-cache-dir -r /ledapi/ledhntr-suite-public/requirements.txt
RUN pip install --no-cache-dir -r /ledapi/ledhntr-suite-public/ledhntr/requirements.txt
RUN pip install --no-cache-dir -e /ledapi/ledhntr-suite-public/ledhntr

# Install plugins
WORKDIR /ledapi/ledhntr-suite-public/ledhntr-plugins
RUN ledhntr install ./typedb_client/
RUN ledhntr install ./shodan/
RUN ledhntr install ./censys/

# Copy the configs to the .ledhntr directory
COPY ledhntr.cfg /home/leduser/.ledhntr/

WORKDIR /ledapi/ledhntr-suite-public/ledapi
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]