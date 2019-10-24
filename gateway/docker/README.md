# Test Stream

I have a test 1KB stream running behind a relay discoverable via
23.202.36.4, and also via [DRIAD](https://tools.ietf.org/html/draft-ietf-mboned-driad-amt-discovery-08),
with group 23.212.185.4->232.1.1.1:5001.

gateway that connects to relay via discovery IP 23.202.36.2:

~~~
DISCIP=23.202.36.4
~~~

or with [driad.py](https://github.com/GrumpyOldTroll/libmcrx/blob/master/driad.py):

~~~
DISCIP=$(./driad.py 23.212.185.4)
~~~

# Methods of connecting

 1. if you only need to handle joins from another container, you can just run
    the multicast through the docker0 bridge, with AMT traffic doing normal
    NAT:

    ~~~
    docker run -d --rm --name amtgw --privileged grumpyoldtroll/amtgw:latest $DISCIP
    ~~~

 2. if you're running something on the host that needs to receive traffic,
    you also need to add a route for your group address to the host which
    gets you to the gateway's input:

    ~~~
    # linux example
    ip route add 224.0.0.0/4 dev docker0
    ~~~

    ~~~
    # mac example (uses docker0's gateway ip):
    route add -net 224.0.0.0/4 172.17.0.1
    ~~~

 3. if you're trying to forward traffic to the host's network, you have to
    connect the container to the host network (so you can receive
    igmp/mld from the host's physical network and forward multicast traffic
    onto it) and _also_ connect via the default bridge to forward traffic.
    the container's default entrypoint looks for a 2nd interface and uses
    it for mcproxy.

    recommended to use a macvlan for this, something like this, with
    enp0s8 as the physical interface for multicast traffic, and
    192.168.56.128/25 as an IP range you can use on that interface for
    sending igmp queries.

    ~~~
    docker network create -d macvlan --subnet=192.168.56.0/24 --ip-range=192.168.56.128/25 --gateway=192.168.56.1 -o parent=enp0s8 macnet

    docker create --rm --name amtgw --privileged grumpyoldtroll/amtgw:latest $DISCIP

    docker network connect macnet amtgw
    docker start amtgw
    ~~~

    If you have multiple interfaces in the host, you might also have to add
    a route to make sure the igmp/mld listening happens on the right interface:

    ~~~
    sudo ip route add 224.0.0.0/24 via 192.168.56.1
    ~~~

# Receiver

this is a receiver that subscribes to ssm traffic (this can test with the #1 mode, above):

~~~
docker run -it --rm --name rx2 grumpyoldtroll/iperf-ssm:latest --server --udp --bind 232.1.1.1 --source 23.212.185.4 --interval 1 --len 1500 --interface eth0
~~~

you can build it, but the docker+docker.io from baseline ubuntu 16.04
doesn't have multi-stage builds, so you may need to install docker-ce:

 * <https://docs.docker.com/install/linux/docker-ce/ubuntu/#set-up-the-repository>

~~~
docker build -t grumpyoldtroll/amtgw-igmp:latest docker-igmpgw/
docker build -t grumpyoldtroll/iperf-ssm:latest docker-iperf-ssm/
~~~

