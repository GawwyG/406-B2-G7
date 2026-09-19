#!/usr/bin/env python3
"""
Mininet topology for the TCP Reset Attack on Video Streaming project (tool #15).

    h1 (client)   \\
                    s1 (LAN switch) --- r1 (router) --- s2 (WAN switch) --- h3 (server)
    h2 (attacker) /

Subnets:
    LAN (h1, h2, r1-eth0): 10.0.1.0/24
    WAN (r1-eth1, h3):     10.0.2.0/24

h1 and h2 share the same OVS switch (s1) -> same L2 broadcast domain, matching
the "attacker on same subnet/switch as client" assumption in the design report.
r1 is a plain Linux host with IP forwarding enabled, bridging the two subnets
at L3 -- it never sees LAN-local (h1<->h2) traffic, only traffic that actually
needs routing.

Run with:  sudo python3 topo.py
"""

from mininet.net import Mininet
from mininet.node import OVSSwitch, Node
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI


class LinuxRouter(Node):
    def config(self, **params):
        super().config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super().terminate()


def build(wan_bw=1, wan_delay_r1='20ms', wan_delay_h3='5ms'):
    """Defaults match the interactive demo; run_experiments.py sweeps
    these to see how network conditions affect the attack's race margin."""
    net = Mininet(switch=OVSSwitch, controller=None, link=TCLink)

    info('*** Adding router\n')
    r1 = net.addHost('r1', cls=LinuxRouter, ip=None)

    info('*** Adding switches\n')
    # failMode='standalone' -> OVS behaves as a normal L2 learning switch
    # with no external controller needed. We layer extra ACL flows on top
    # of this later for the IP Source Guard defense demo.
    s1 = net.addSwitch('s1', failMode='standalone')  # LAN switch (client+attacker)
    s2 = net.addSwitch('s2', failMode='standalone')  # WAN switch (router+server)

    info('*** Adding hosts\n')
    h1 = net.addHost('h1', ip='10.0.1.10/24', defaultRoute='via 10.0.1.1')  # client
    h2 = net.addHost('h2', ip='10.0.1.20/24', defaultRoute='via 10.0.1.1')  # attacker
    h3 = net.addHost('h3', ip='10.0.2.10/24', defaultRoute='via 10.0.2.1')  # server

    info('*** Creating links\n')
    # LAN links (h1, h2, r1's LAN side) are left at full emulated speed --
    # this is the attacker's "short path" advantage in the race.
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(r1, s1, intfName1='r1-eth0')
    # WAN links are bandwidth/delay-limited to emulate a realistic
    # internet path to the streaming server -- the "long path" the real
    # server response has to take, and what makes the video stream over
    # tens of seconds instead of downloading instantly.
    net.addLink(r1, s2, intfName1='r1-eth1', bw=wan_bw, delay=wan_delay_r1)
    net.addLink(h3, s2, bw=wan_bw, delay=wan_delay_h3)
    # h2's second interface, used only as the OVS mirror's output-port
    # for sniffing h1's traffic. No IP address. Added last so the
    # existing port numbers (s1-eth1=h1, s1-eth2=h2, s1-eth3=r1) don't
    # shift; this one becomes s1-eth4.
    #
    # Has to be separate from h2-eth0: making h2's primary interface
    # double as the mirror's output-port broke its own outgoing traffic
    # entirely (a port can't be both actively-transmitting and a mirror
    # destination here). h2-eth0 stays ordinary, h2-eth1 is a passive tap.
    net.addLink(h2, s1)

    net.build()

    r1.setIP('10.0.1.1/24', intf='r1-eth0')
    r1.setIP('10.0.2.1/24', intf='r1-eth1')

    net.start()
    return net


if __name__ == '__main__':
    setLogLevel('info')
    net = build()
    info('\n*** Topology up. Try: pingall\n')
    info('*** h1=client(10.0.1.10) h2=attacker(10.0.1.20) h3=server(10.0.2.10) r1=router\n')
    CLI(net)
    net.stop()
