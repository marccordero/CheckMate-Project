# Image
FROM ubuntu:18.04

# Commands
RUN apt-get update -y
RUN apt-get install python python-dev python-pip wget apt-transport-https software-properties-common unzip nano -y && \
    pip install --upgrade pip && \
    pip install --upgrade setuptools && \
    pip install "regex<2022.1.18" && \
    pip install grpcio && \
    pip install -U https://github.com/decalage2/ViperMonkey/archive/master.zip
RUN wget -q "https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb" && \
    dpkg -i packages-microsoft-prod.deb && \
    apt update -y && \
    apt install powershell -y && \
    mkdir /app && \
    mkdir /app/samples && \
    mkdir /app/converter && \
    mkdir /app/converter/results
COPY /converter /app/converter
COPY /samples /app/samples
WORKDIR /app

# Volumes
VOLUME ["/app/converter/results"]

# Start
ENTRYPOINT ["/bin/bash"]