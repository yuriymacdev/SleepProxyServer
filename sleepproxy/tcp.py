from functools import partial
import logging

from scapy.all import IP, TCP

import sleepproxy.manager
from sleepproxy.sniff import SnifferThread
from sleepproxy.wol import wake

_HOSTS = {}

def handle(mac, addresses, iface):
    logging.info("Now handling TCP SYNs for %s:%s on %s" % (mac, addresses, iface))

    if mac in _HOSTS:
        logging.debug("Ignoring already managed host %s" % (mac, ))

    for address in addresses:
        thread = SnifferThread(
            filterexp="tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0 and dst host %s" % (address, ),
            prn=partial(_handle_packet, mac, address),
            iface=iface,
        )
        _HOSTS[mac] = thread
        thread.start()

def forget(mac):
    logging.info("Removing host %s from TCP handler" % (mac, ))
    if mac not in _HOSTS:
        logging.info("I don't seem to know about %s, ignoring" % (mac, ))
        return
    _HOSTS[mac].stop()
    del _HOSTS[mac]

def _handle_packet(mac, address, packet):
    """Do something with a SYN for the other machine!"""
    if not (IP in packet and TCP in packet):
        return
    if packet[IP].dst != address:
        logging.debug("Sniffed a TCP SYN for the wrong address?: %s" % packet.show() )
        return
    logging.debug(packet.display())
    wake(mac)

    # TODO: Check if it awoke?
    sleepproxy.manager.forget_host(mac)
