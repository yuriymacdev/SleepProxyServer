from time import sleep
import sleepproxy.mdns as mdns
import sleepproxy.arp as arp
import sleepproxy.tcp as tcp

import logging
def print_hosts(*args):
    logging.warn(mdns._HOSTS)
    logging.warn(arp._HOSTS)
    logging.warn(tcp._HOSTS)

def manage_host(info):
    mdns.handle(info['othermac'], info['records'])
    sleep(5) #prevent potential race condition where host is woken up right after NSUPDATE by backlogged ARP/TCP requests 
    arp.handle(info['othermac'], info['addresses'], info['mymac'], info['myif'])
    tcp.handle(info['othermac'], info['addresses'], info['myif'])

def forget_host(mac):
    mdns.forget(mac)
    arp.forget(mac)
    tcp.forget(mac)
