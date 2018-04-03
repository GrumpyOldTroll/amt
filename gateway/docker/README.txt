
# I have a test 1KB stream running behind a relay discoverable via
# 23.202.36.2 (which will map to an IP that matches r2v4.amt.akadns.net),
# with source->group = 23.212.185.2->232.43.211.200.

# gateway that connects to relay via discovery IP 23.202.36.2:
IP=23.202.36.2; docker run -d --rm --name amtgw-$IP --privileged grumpyoldtroll/amtgw:latest $IP

# receiver that subscribes to the traffic:
docker run -it --rm --name rx2 grumpyoldtroll/iperf-ssm:latest --server --udp --bind 232.43.211.200 --source 23.212.185.2 --interval 1 --len 1500 --interface eth0

# you can build it, but the docker+docker.io from baseline ubuntu 16.04
# doesn't have multi-stage builds, so you may need to install docker-ce:
# https://docs.docker.com/install/linux/docker-ce/ubuntu/#set-up-the-repository
docker build -t grumpyoldtroll/amtgw-igmp:latest docker-igmpgw/
docker build -t grumpyoldtroll/iperf-ssm:latest docker-iperf-ssm/

