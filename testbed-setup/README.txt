Testbed setup instructions

This describes how to reproduce the testbed setup from the IETF 98
hackathon. It's sort of my own little multicast-enabled ISP.
Network diagrams from AMT-hackathon98.pptx may be useful.

I ran 2 cisco CSR1000v images to check PIM connectivity for a realistic
fanout network, even though it's only 1 hop. You likely can see what
you want with a simpler test setup unless you're operating an ISP.

If this seems like way too much and you just wanted to mess with the
amt code a bit, you might want to try simpler-testbed.txt.

This file refers to the several other files under testbed-setup.

Prerequisites:
- a machine with 3 network interfaces and more than 8G of ram.
  (8G for the 2 vms, the rest for the host.)

Get the latest csr1000v iso. While logged into your cisco account,
go to https://software.cisco.com/download/navigator.html, under:
Products/
   Routers/
      Virtual Routers/
         Cloud Services Router 1000V Series:
pick "IOS XE Software".

If you're lucky, you get to download their recommended current Denali iso.
Here's hashes of the one I get on March 9 2017:

$ shasum -a 256 csr1000v-universalk9.03.16.05.S.155-3.S5-ext.iso 
$ f6839f1a7867c4bcb05abf18112c96d8c508c9896d303d1595cc608dd7e76b4b  csr1000v-universalk9.03.16.05.S.155-3.S5-ext.iso
$ shasum csr1000v-universalk9.03.16.05.S.155-3.S5-ext.iso 
$ 492df39aed8da0cd0aeebcd38a4aa097fa436405  csr1000v-universalk9.03.16.05.S.155-3.S5-ext.iso
$ md5sum csr1000v-universalk9.03.16.05.S.155-3.S5-ext.iso 
$ 1fd1bcbbb89754ed9b51b3059e6aba4d  csr1000v-universalk9.03.16.05.S.155-3.S5-ext.iso

I started with a freshly installed ubuntu-16.04-server-amd64.iso,
with ssh server, vm hosting, and system utilities pre-installed,
nothing special. Then updated and restarted:
sudo apt update && sudo apt dist-upgrade -y && sudo apt autoremove -y

note: paths below assume you are working in /home/akamai, and that
you have copied the files that are hopefully with these instructions
into that directory also. You may have to adjust for your environment,
rather than copy/paste commands unmodified. There is no reason you have
to use the string "akamai" anywhere, feel free to replace with your own
name, and to use something different again where it's a password.

install tftp
$ sudo apt install -y xinetd tftpd
$ sudo cp etc_xinetd.d_tftp /etc/xinetd.d/tftp
$ sudo service xinetd restart
$ mkdir tftp
# ce="customer edge", pe="provider edge"
$ cp csrce.conf tftp/csrce-initial.conf
$ cp csrpe.conf tftp/csrpe-initial.conf

tftp was weirdly finicky about permissions, so I opened wide. In a less
controlled environment you might want to figure out how to configure it
to get permissions better, or turn this on temporarily only when you
encounter trouble getting it to work. Use with caution:
$ chmod 0777 tftp
$ chmod 0777 tftp/*

install and bring up virtual machines:
$ sudo apt install -y virtinst

$ mkdir jake_vm
$ qemu-img create -f qcow2 jake_vm/csrpe.qcow2 8G
$ virt-install --name=csrpe --os-type=linux --arch=x86_64 --cpu host --vcpus=1 --hvm --ram=4096 --disk path=/home/akamai/jake_vm/csrpe.qcow2,bus=ide,format=qcow2 --cdrom=/home/akamai/csr1000v-universalk9.03.16.05.S.155-3.S5-ext.iso --network bridge=virbr0,model=virtio --noreboot --graphics vnc,listen=localhost,port=16906,password=amt

$ qemu-img create -f qcow2 jake_vm/csrce.qcow2 8G
$ virt-install --name=csrce --os-type=linux --arch=x86_64 --cpu host --vcpus=1 --hvm --ram=4096 --disk path=/home/akamai/jake_vm/csrce.qcow2,bus=ide,format=qcow2 --cdrom=/home/akamai/csr1000v-universalk9.03.16.05.S.155-3.S5-ext.iso --network bridge=virbr0,model=virtio --noreboot --graphics vnc,listen=localhost,port=16907,password=amt

network hooks so that multicast is forwarded over internal bridge, even
without igmp (between routers uses pim):
$ sudo cp etc_libvirt_hooks_network /etc/libvirt/hooks/network
$ sudo chmod +x /etc/libvirt/hooks/network
$ sudo service libvirt-bin restart

set up internal bridge:
$ virsh net-define between-net.xml
$ virsh net-autostart between-net
$ virsh net-start between-net

configure bridges to physical interfaces:
$ sudo sh -c "echo '\nsource /etc/network/interfaces.d/*' >> /etc/network/interfaces"

p1p1 is physical interface with upstream senders
p4p1 is physical interface with downstream receivers
edit these files to match interface names for your testbed, then:
$ sudo cp etc_network_interfaces.d_br0-p4p1.conf /etc/network/interfaces.d/br0-p4p1.conf
$ sudo cp etc_network_interfaces.d_br1-p1p1.conf /etc/network/interfaces.d/br1-p1p1.conf

reboot or restart networking, so you have br0/br1
and restart routers:
$ virsh start csrce; virsh start csrpe

these attach-interface calls are in order. (router config referring to
gig1 and gig2 relies on this ordering, if you change it you'll have to
change the config also).
(doing this in the initial vm definition instead of afterwards as an
attach-interface ended up with an unreliable order for me, some time
ago with an older ubuntu--that may or may not be fixed by now.)

$ virsh attach-interface --domain csrpe --type bridge --source br1 --model virtio --persistent --live --config
$ virsh attach-interface --domain csrpe --type bridge --source virbr1 --model virtio --persistent --live --config

$ virsh attach-interface --domain csrce --type bridge --source br0 --model virtio --persistent --live --config
$ virsh attach-interface --domain csrce --type bridge --source virbr1 --model virtio --persistent --live --config

log into routers. from your remote macbook:
$ ssh -L 16906:localhost:16906 -L 16907:localhost:16907 akamai@amtlabdemo
then:
$ open vnc://localhost:16906
(password from the virt-install command)

on other platforms, you can use another vnc approach and possibly ssh
approach, but it's similar. With vnc, you should have a window that
configures the router.

inside router:
en
conf t
  int gig 1
  ip addr 192.168.122.6 255.255.255.0
  no shutdown
  end
copy tftp://192.168.122.1/csrpe-initial.conf running-config
conf t
  int gig 2
  no shutdown
  int gig 3
  no shutdown
  end
copy running-config startup-config
write

Do the same again with the 2nd router:
with vnc://localhost:16907, and with csrce-initial.conf instead of csrpe,
and with 192.168.122.7 instead of .6

get and install licenses:
http://www.cisco.com/c/en/us/td/docs/routers/csr1000/software/configuration/b_CSR1000v_Configuration_Guide/b_CSR1000v_Configuration_Guide_chapter_01000.html
(without this step, you can still receive traffic as below, but you will
be limited to 100kbps, insufficient to play video)

downstream receivers should now be able to:
1. receive native multicast from upstream senders:
  - sender with 10.5.5.91 (via dhcp from csrpe):
    (with git clone https://github.com/GrumpyOldTroll/iperf-ssm.git)
    iperf-ssm/src/iperf --client 232.10.5.91 --udp --ttl 30 --bandwidth 1K --bind 10.5.5.91 --len 125 --time 900
  - receiver with 10.7.7.91 (via dhcp from csrce) and eth0:
    iperf-ssm/src/iperf --server --udp --single_udp --bind 232.10.5.91 --source 10.5.5.91 --interface eth0 --interval 1 --len 125

See setup-dev-vm.txt for building the openwrt component.

