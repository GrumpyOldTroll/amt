FROM ubuntu:latest
MAINTAINER Jake Holland <jholland@akamai.com>

# multi-stage build --jake 2018-04-02
# https://docs.docker.com/develop/develop-images/multistage-build/#use-multi-stage-builds

# stage 0
RUN apt-get update && apt-get install -y build-essential git automake

RUN apt-get install -y cmake
RUN git clone https://github.com/GrumpyOldTroll/mcproxy && \
    cd mcproxy && cmake . && make

RUN apt-get install -y libevent-dev
RUN git clone https://github.com/GrumpyOldTroll/amt && \
    cd amt && autoreconf -f -i && ./configure && make

# stage 1
FROM ubuntu:latest
COPY --from=0 /amt/gateway/amtgwd /bin/amtgwd
COPY --from=0 /mcproxy/mcproxy-bin /bin/mcproxy
RUN apt-get update && apt-get install -y iproute2 libevent-dev

COPY mcproxy_v4.conf /etc/mcproxy_v4.conf
COPY mcproxy_v6.conf /etc/mcproxy_v6.conf
COPY run_amtgwd /bin/run_amtgwd
RUN chmod 0755 /bin/run_amtgwd

ENTRYPOINT ["/bin/run_amtgwd"]

