# Image
FROM ubuntu:18.04

# Commands
RUN apt-get update --fix-missing -y
RUN apt-get install python3 python-dev python3-pip wget unzip nano software-properties-common unzip -y && \
    pip3 install --upgrade --ignore-installed pip setuptools && \
    pip3 install setuptools-rust && \
    pip3 install -U oletools[full]
RUN wget -q "https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb" && \
    dpkg -i packages-microsoft-prod.deb && \
    apt update -y && \
    apt install powershell -y && \
    mkdir /app && \
    mkdir /app/converter && \
    mkdir /app/results 
COPY /samples /app/samples
COPY /converter /app/converter
WORKDIR /app

# Volumes
VOLUME ["/app/results"]

# Start
ENTRYPOINT ["/bin/bash"]