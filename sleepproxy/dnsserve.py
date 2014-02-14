"""A NSUPDATE server class for gevent"""
# Copyright (c) 2013 Russell Cloran
# Copyright (c) 2014 Joey Korkames

import struct
import logging

import dns.message
import dns.reversename
import ipaddress
import netifaces

from sleepproxy.manager import manage_host

from gevent.server import DatagramServer
#https://github.com/surfly/gevent/blob/master/gevent/server.py#L106

#import socket

__all__ = ['SleepProxyServer']

class SleepProxyServer(DatagramServer):

    # #@classmethod
    # #def get_listener(self, address, family=None):
    # #    #return _udp_socket(address, reuse_addr=self.reuse_addr, family=family)
    # #    sock = socket.socket(family=family, type=socket.SOCK_DGRAM)
    # #    #if family == socket.AF_INET6: logging.warn("dual-stacking!"); sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
    # #    if family == socket.AF_INET6: logging.warn("disabling dual-stacking!"); sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, True)
    # #    sock.bind(address)
    # #    return sock

    def handle(self, message, raddress):
        try:
            message = dns.message.from_wire(message)
        except:
            logging.warning("Error decoding DNS message")
            return
    
        if message.edns < 0:
            logging.debug("Received non-EDNS message, ignoring")
            return
    
        if not (message.opcode() == 5 and message.authority):
            logging.debug("Received non-UPDATE message, ignoring")
            return
    
        info = {'records': [], 'addresses': []}
    
        # Try to guess the interface this came in on
        #   todo - precompute this table on new()?
        for iface in netifaces.interfaces():
            ifaddresses = netifaces.ifaddresses(iface)
            for af, addresses in ifaddresses.items():
                if af not in (netifaces.AF_INET, netifaces.AF_INET6): continue
                for address in addresses:
                    iface_net = ipaddress.ip_interface(address['addr'] + '/' + address['netmask'])
                    if ipaddress.ip_address(raddress[0]) in iface_net:
                        info['mymac'] = ifaddresses[netifaces.AF_LINK][0]['addr']
                        info['myif'] = iface
    
        for rrset in message.authority:
            info['records'].append(rrset)
            self._add_addresses(info, rrset)
    
        logging.debug('NSUPDATE START--\n\n' + message.to_text() + '\n\n--NSUPDATE END')
    
        for option in message.options: #EDNS0
            if option.otype == 2: # http://files.dns-sd.org/draft-sekar-dns-ul.txt
                info['ttl'] = struct.unpack("!L", option.data) #send-WOL-no-later-than timer TTL
            if option.otype == 4:
                info['othermac'] = option.data.encode('hex_codec')[4:] #WOL target mac
                #if option.data[1] > 18: #[5] password required in wakeup packet
                #http://tools.ietf.org/id/draft-cheshire-edns0-owner-option-00.txt
                #  mDNS.c:SendSPSRegistrationForOwner() doesn't seem to add a password
    
        # TODO: check for DNSSEC 'do' flag
    
        # TODO: endsflags seems to indicate some other TTL
    
        self._answer(raddress, message)

        # TODO: Better composability
        manage_host(info)
        
    def _add_addresses(self, info, rrset):
        # Not sure if this is the correct way to detect addresses.
        if rrset.rdtype != dns.rdatatype.PTR or rrset.rdclass not in [dns.rdataclass.IN, 32769]: return
    
        #if not rrset.name.to_text().endswith('.in-addr.arpa.'): return #TODO: support SYN sniffing for .ip6.arpa. hosts
        if not rrset.name.to_text().endswith('.arpa.'): return #all we care about are reverse-dns records
    
        info['addresses'].append(dns.reversename.to_address(rrset.name))
    
    def _answer(self, address, query):
        response = dns.message.make_response(query)
        self.socket.sendto(response.to_wire(), address)
