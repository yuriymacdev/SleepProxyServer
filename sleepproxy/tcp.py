from functools import partial
import logging

from scapy.all import IP, TCP

import sleepproxy.manager
from sleepproxy.sniff import SnifferThread
from sleepproxy.wol import wake
from time import sleep

_HOSTS = {}

def handle(mac, addresses, iface):
    if mac in _HOSTS:
        logging.debug("Ignoring already managed TCP host {}" .format (mac, ))

    logging.info("Now handling TCP SYNs for {}:{} on {}".format (mac, addresses, iface))

    for address in addresses:
        #we can be fancier, wake on port 22 with plain packets, not just syn
        #http://www.opensource.apple.com/source/mDNSResponder/mDNSResponder-522.1.11/mDNSCore/mDNS.c mDNSCoreReceiveRawTransportPacket()
        if ':' in address: #ipv6
            expr = "ip6[6]=6 && ip6[53]&4!=0 and ip6[6]=6 && ip6[53]&1=0 and dst host {}".format(address) #ipv6 can have multiple headers, so no tcp* shortcuts in pcap-filter
        else:
            expr = "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0 and dst host {}".format(address)
        thread = SnifferThread( filterexp=expr, prn=partial(_handle_packet, mac, address), iface=iface) #using a callback, but nut not doing it async
        _HOSTS[mac] = thread
        thread.start() #make this a greenlet?

def forget(mac):
    logging.info("Removing host {} from TCP handler".format(mac, ))
    if mac not in _HOSTS:
        logging.info("I don't seem to know about {}, ignoring".format (mac, ))
        return
    _HOSTS[mac].stop()
    del _HOSTS[mac]

def _handle_packet(mac, address, packet):
    """Do something with a SYN for the other machine!"""
    if not (IP in packet and TCP in packet):
        return
    if packet[IP].dst != address:
        logging.debug("Sniffed a TCP SYN for the wrong address?: {}".format( packet.show()) )
        return
    #logging.debug(packet.display())
    sleepproxy.manager.mdns.forget(mac) # pre-emptively drop adv to keep the mac from de-colliding its name
    sleep(0.4)
    wake(mac) #retry=15?
    #sleepproxy.manager.forget_host(mac) 

