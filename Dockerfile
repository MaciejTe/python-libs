FROM python:3.5-alpine

RUN apk add gcc linux-headers libc-dev libffi-dev openssl-dev make
RUN apk add ccache libsodium-dev

# for zeep Python library
RUN apk add libxml2-dev libxslt-dev git

COPY . /python_libs/
WORKDIR python_libs/

RUN SODIUM_INSTALL=system pip install pynacl
RUN pip install -e .
WORKDIR /
