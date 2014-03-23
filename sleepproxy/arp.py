from functools import partial
import logging

from scapy.all import ARP, Ether, sendp

import sleepproxy.manager
from sleepproxy.sniff import SnifferThread

_HOSTS = {}

def handle(othermac, addresses, mymac, iface):
    if othermac in _HOSTS:
        logging.info("I already seem to be managing %s, ignoring" % othermac)
        return
    logging.info('Now handling ARPs for %s:%s on %s' % (othermac, addresses, iface))

    for address in addresses:
        if ':' in address: #ipv6
            expr = "ip6 && icmp6 && (ip6[40] == 135 || ip6[40] == 136) and host %s" % (address) #ipv6 uses ndp, not arp
        else:
            expr = "arp host %s" % (address)
        thread = SnifferThread( filterexp=expr, prn=partial(_handle_packet, address, mymac, othermac), iface=iface,)
        _HOSTS[othermac] = thread
        thread.start()

def forget(mac):
    logging.info("Removing %s from ARP handler" % (mac, ))
    if mac not in _HOSTS:
        logging.info("I don't seem to be managing %s" % (mac, ))
        return
    _HOSTS[mac].stop()
    del _HOSTS[mac]

def _handle_packet(address, mac, sleeper, packet):
    if ARP not in packet:
        # I don't know how this happens, but I've seen it
        return
    if packet.hwsrc.replace(':','') == sleeper:
        logging.info("sleeper has awakened, forgetting %s" % sleeper)
        sleepproxy.manager.forget_host(sleeper)
        return
    if packet[ARP].op != ARP.who_has:
        return
    if packet[ARP].pdst != address:
        logging.debug("Skipping packet with pdst %s != %s" % (packet[ARP].pdst, address, ))
        return
    logging.debug(packet.display())

    ether = packet[Ether]
    arp = packet[ARP]

    reply = Ether(
        dst=ether.src, src=mac) / ARP(
            op="is-at",
            psrc=arp.pdst,
            pdst=arp.psrc,
            hwsrc=mac,
            hwdst=packet[ARP].hwsrc)
    logging.warn("Spoofing ARP response for %s to %s" % (arp.pdst, packet[ARP].psrc))
    sendp(reply)
