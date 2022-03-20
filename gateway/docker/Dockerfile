FROM ubuntu:latest
MAINTAINER Jake Holland <jholland@akamai.com>

# multi-stage build --jake 2018-04-02
# https://docs.docker.com/develop/develop-images/multistage-build/#use-multi-stage-builds

# stage 0
ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC
ENV APT_LISTCHANGES_FRONTEND=none
RUN \
  echo 'libc6 libraries/restart-without-asking boolean true' | debconf-set-selections; \
  apt-get update; \
  apt-get --allow-downgrades --allow-remove-essential --allow-change-held-packages -fuy dist-upgrade

#  apt-get --allow-downgrades --allow-remove-essential --allow-change-held-packages -o Dpkg::Options::="--force-confold" --force-yes -o Dpkg::Options::="--force-confdef" -fuy dist-upgrade

RUN apt-get install -y libevent-dev

RUN apt-get install -y build-essential git automake cmake

RUN git clone https://github.com/GrumpyOldTroll/mcproxy && \
    cd mcproxy && cmake . && make

COPY . /amt
RUN cd /amt && autoreconf -f -i && ./configure && make

#RUN git clone https://github.com/GrumpyOldTroll/amt && \
#    cd amt && autoreconf -f -i && ./configure && make

# stage 1
FROM ubuntu:latest

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC
ENV APT_LISTCHANGES_FRONTEND=none
RUN \
  echo 'libc6 libraries/restart-without-asking boolean true' | debconf-set-selections; \
  apt-get update; \
  apt-get --allow-downgrades --allow-remove-essential --allow-change-held-packages -fuy dist-upgrade

RUN apt-get install -y libevent-dev

RUN apt-get install -y iproute2

COPY gateway/docker/mcproxy_v4.conf /etc/mcproxy_v4.conf
COPY gateway/docker/mcproxy_v6.conf /etc/mcproxy_v6.conf
COPY gateway/docker/run_amtgwd /bin/run_amtgwd

COPY --from=0 /amt/gateway/amtgwd /bin/amtgwd
COPY --from=0 /mcproxy/mcproxy-bin /bin/mcproxy

RUN chmod 0755 /bin/run_amtgwd

ENTRYPOINT ["/bin/run_amtgwd"]

