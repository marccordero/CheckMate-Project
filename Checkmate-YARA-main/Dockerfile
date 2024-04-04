# Image
FROM alpine:3.16

# Commands
ENV YARA_VERSION 4.2.3
ENV SAMPLEDIR Samples 
ENV RULEDIR Rules
RUN apk add --no-cache openssl file jansson bison python3 tini su-exec p7zip
RUN apk add --no-cache -t .build-deps py3-setuptools \
    openssl-dev \
    jansson-dev \
    python3-dev \
    build-base \
    libc-dev \
    file-dev \
    automake \
    autoconf \
    libtool \
    flex \
    git \
    git && \
    git clone --recursive --branch v$YARA_VERSION https://github.com/VirusTotal/yara.git && \
    cd yara && \
    ./bootstrap.sh && \
    ./configure && \
    make && \
    make install && \
    ./configure --enable-cuckoo \
    --enable-magic \
    --enable-dotnet  && \
    make && \
    make install && \
    cd .. && \
    mkdir /app && \
    mkdir /app/samples && \
    mkdir /app/rules && \
    mkdir app/converter
COPY /$RULEDIR/ /app/rules/
COPY /$SAMPLEDIR/ /app/samples/
COPY /Converter/ /app/converter/
WORKDIR /app

# Volumes
VOLUME ["/app/samples"]
VOLUME ["/app/rules"]

# Start
ENTRYPOINT ["sh"]
