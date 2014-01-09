"""A NSUPDATE server class for gevent"""
# Copyright (c) 2013 Russell Cloran
# Copyright (c) 2013 Joey Korkames

import struct
import logging

import dns.message
import dns.reversename
import IPy
import netifaces

from sleepproxy.manager import manage_host

from gevent.server import DatagramServer
#https://github.com/surfly/gevent/blob/master/gevent/server.py#L106

__all__ = ['SleepProxyServer']

class SleepProxyServer(DatagramServer):

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
        for iface in netifaces.interfaces():
            ifaddresses = netifaces.ifaddresses(iface)
            for af, addresses in ifaddresses.items():
                if af != 2:  # AF_INET
                    continue
                for address in addresses:
                    net = IPy.IP(address['addr']).make_net(address['netmask'])
                    if IPy.IP(raddress[0]) in net:
                        info['mymac'] = ifaddresses[17][0]['addr']
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
        if rrset.rdtype != dns.rdatatype.PTR or rrset.rdclass not in [dns.rdataclass.IN, 32769]:
            return
    
        # Meh.
        if not rrset.name.to_text().endswith('.in-addr.arpa.'): #TODO: support .ip6.arpa.
            return
    
        info['addresses'].append(dns.reversename.to_address(rrset.name))
    
    def _answer(self, address, query):
        response = dns.message.make_response(query)
        self.socket.sendto(response.to_wire(), address)
