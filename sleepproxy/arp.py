from functools import partial

from scapy.all import ARP, Ether, sendp

import sleepproxy.manager
from sleepproxy.sniff import SnifferThread

_HOSTS = {}

def handle(othermac, addresses, mymac, iface):
    print 'Pretending to handle arp for %s:%s on %s' % (othermac, addresses, iface)

    if othermac in _HOSTS:
        print "I already seem to be managing %s, ignoring" % othermac
        return

    for address in addresses:
        if ':' in address:
            # TODO: Handle IP6
            continue
        thread = SnifferThread(
            filterexp="arp host %s" % (address, ),
            prn=partial(_handle_packet, address, mymac, othermac),
            iface=iface,
        )
        _HOSTS[othermac] = thread
        thread.start()

def forget(mac):
    print "Pretending to forget %s in ARP" % (mac, )
    if mac not in _HOSTS:
        print "I don't seem to be managing %s" % (mac, )
        return
    _HOSTS[mac].stop()
    del _HOSTS[mac]

def _handle_packet(address, mac, sleeper, packet):
    if ARP not in packet:
        # I don't know how this happens, but I've seen it
        return
    if packet.hwsrc.replace(':','') == sleeper:
        print "sleeper has awakened, forgetting %s" % sleeper
        sleepproxy.manager.forget_host(sleeper)
        return
    if packet[ARP].op != ARP.who_has:
        return
    if packet[ARP].pdst != address:
        print "Skipping packet with pdst %s != %s" % (packet[ARP].pdst, address, )
        return
    #print packet.display()

    ether = packet[Ether]
    arp = packet[ARP]

    reply = Ether(
        dst=ether.src, src=mac) / ARP(
            op="is-at",
            psrc=arp.pdst,
            pdst=arp.psrc,
            hwsrc=mac,
            hwdst=packet[ARP].hwsrc)
    print "Sending ARP response for %s" % (arp.pdst, )
    sendp(reply)
