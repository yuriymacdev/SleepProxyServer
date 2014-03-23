"""A NSUPDATE server class for gevent"""
# Copyright (c) 2013 Russell Cloran
# Copyright (c) 2014 Joey Korkames

import traceback
import struct
import logging

import dns.name
import dns.flags
import dns.message
import dns.reversename
import dns.edns

import ipaddress
import netifaces

import binascii

import pdb

# http://www.opensource.apple.com/source/mDNSResponder/mDNSResponder-522.1.11/mDNSCore/mDNS.c
# [SLEEPER]BeginSleepProcessing(),NetWakeResolve(),SendSPSRegistration() -> [SPS SERVER]mDNSCoreReceiveUpdate() -> [SLEEPER]mDNSCoreReceive(),mDNSCoreReceiveUpdateR()

# http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
dns.edns.UL = 2
dns.edns.OWNER = 4

#http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-13#4500 in query, 7500L in response
#dns.flags._edns_by_text.update({'??':7500L})
#dns.flags._edns_by_value.update({'7500L':'??'})
#http://tools.ietf.org/html/rfc6891#section-6.1.3

class UpdateLeaseOption(dns.edns.Option):
    """EDNS option for Dynamic DNS Update Leases
http://tools.ietf.org/html/draft-sekar-dns-ul-01"""
    def __init__(self, lease):
        super(UpdateLeaseOption, self).__init__(dns.edns.UL)
        self.lease = lease

    def to_wire(self, file):
        data = struct.pack("!L", self.lease)
        file.write(data)

    @classmethod
    def from_wire(cls, otype, wire, current, olen):
        data = wire[current:current + olen]
        (lease,) = struct.unpack("!L", data)
        return cls(lease)

    def __repr__(self):
        return "%s[OPT#%s](%s)" % (
            self.__class__.__name__,
            self.otype,
            self.lease
        )

dns.edns._type_to_class.update({dns.edns.UL: UpdateLeaseOption})

#SetupOwnerOpt mDNS.c
class OwnerOption(dns.edns.Option):
    """EDNS option for DNS-SD Sleep Proxy Service client mac address hinting
http://tools.ietf.org/html/draft-cheshire-edns0-owner-option-00"""
    def __init__(self, ver=0, seq=1, pmac=None, wmac=None, passwd=None):
        super(OwnerOption, self).__init__(dns.edns.OWNER)
        self.seq = seq
        self.ver = ver
        self.pmac = self._mac2text(pmac)
        self.wmac = self._mac2text(wmac)
        self.passwd = passwd

    @staticmethod
    def _mac2text(mac):
        if not mac: return mac
        #if len(mac) == 6: mac.encode('hex') #this was a wire-format binary
        mac = binascii.hexlify(mac)
        return mac.lower().translate(None,'.:-') #del common octet delimiters

    def to_wire(self, file):
        data = '' + ver + seq
        #data += self.pmac.decode('hex')
        data += binascii.unhexlify(self.pmac)
        if self.pmac != self.wmac:
           data += self.wmac.decode('hex')
           if passwd: data += passwd

        file.write(data)

    @classmethod
    def from_wire(cls, otype, wire, current, olen):
        data = wire[current:current + olen]
        if olen == 20:
           opt = (ver, seq, pmac, wmac, passwd) = struct.unpack('!BB6s6s6s',data)
        elif olen == 18:
           opt = (ver, seq, pmac, wmac, passwd) = struct.unpack('!BB6s6s4s',data)
        elif olen == 14:
           opt = (ver, seq, pmac, wmac) = struct.unpack("!BB6s6s",data)
        elif olen == 8:
           opt = (ver, seq, pmac) = struct.unpack("!BB6s",data)

        return cls(*opt)

    def __repr__(self):
        return "%s[OPT#%s](%s, %s, %s, %s, %s)" % (
            self.__class__.__name__,
            self.otype,
            self.ver,
            self.seq,
            self.pmac,
            self.wmac,
            self.passwd
        )

dns.edns._type_to_class.update({dns.edns.OWNER: OwnerOption})

from sleepproxy.manager import manage_host

from gevent.server import DatagramServer
#https://github.com/surfly/gevent/blob/master/gevent/server.py#L106

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
        except: #no way to just catch dns.exceptions.*
            logging.warning("Error decoding DNS message from %s" % raddress[0])
            logging.debug(traceback.format_exc())
            return
    
        if message.edns < 0:
            logging.warning("Received non-EDNS message from %s, ignoring" % raddress[0])
            return
    
        if not (message.opcode() == 5 and message.authority):
            logging.warning("Received non-UPDATE message from %s, ignoring" % raddress[0])
            return
    
        logging.debug("Received SPS registration from %s, parsing" % raddress[0])

        info = {'records': [], 'addresses': []}
    
        # Try to guess the interface this came in on
        #   todo - precompute this table on new()?
        for iface in netifaces.interfaces():
            ifaddresses = netifaces.ifaddresses(iface)
            for af, addresses in ifaddresses.items():
                if af not in (netifaces.AF_INET, netifaces.AF_INET6): continue
                for address in addresses:
                    mask = address['netmask']
                    if af == netifaces.AF_INET6: mask = (mask.count('f') * 4) # convert linux masks to prefix length...gooney
                    if address['addr'].find('%') > -1: continue #more linux ipv6 stupidity
                    iface_net = ipaddress.ip_interface('%s/%s' % (address['addr'], mask)).network
                    if ipaddress.ip_address(raddress[0]) in iface_net:
                        info['mymac'] = ifaddresses[netifaces.AF_LINK][0]['addr']
                        info['myif'] = iface
    
        for rrset in message.authority:
            rrset.rdclass %= dns.rdataclass.UNIQUE #remove cache-flush bit
            info['records'].append(rrset)
            self._add_addresses(info, rrset)
    
        logging.debug('NSUPDATE START--\n\n%s\n\n%s\n\n--NSUPDATE END' % (message,message.options))
 
        #not getting a nice text parse of OPT record in additional, just shows as "eflags"
        #[(o.otype, o.data) for o in query.options]
        #query.find_rrset(3,'.',1,dns.rdatatype.OPT)
  
        for option in message.options:
            if option.otype == dns.edns.UL:
                info['ttl'] = option.lease #send-WOL-no-later-than timer TTL
            if option.otype == dns.edns.OWNER:
                info['othermac'] = option.pmac #WOL target mac
                #if option.passwd: # password required in wakeup packet
                #  mDNS.c:SendSPSRegistrationForOwner() doesn't seem to add a password
    
        self._answer(raddress, message)

        # TODO: Better composability
        manage_host(info)
        
    def _add_addresses(self, info, rrset):
        if rrset.rdtype != dns.rdatatype.PTR: return
        if rrset.rdclass != dns.rdataclass.IN: return
    
        #if not rrset.name.to_text().endswith('.in-addr.arpa.'): return #TODO: support SYN sniffing for .ip6.arpa. hosts
        if not rrset.name.to_text().endswith('.arpa.'): return #all we care about are reverse-dns records
    
        info['addresses'].append(dns.reversename.to_address(rrset.name))
    
    def _answer(self, address, query):
        #pdb.set_trace()
        response = dns.message.make_response(query)
        #needs a single OPT record to confirm registration:  0 TTL    4500   48 . OPT Max 1440 Lease 7200 Vers 0 Seq  21 MAC D4:9A:20:DE:9D:38
        response.flags = dns.flags.QR | dns.opcode.to_flags(dns.opcode.UPDATE)
        #response.ednsflags |= #4500 TTL ('kStandardTTL' = 75 min) + ?? extended-rcode = 7200L ?? 7200 (2 hrs) is uDNS default lease
        response.use_edns(edns=True, ednsflags=dns.rcode.NOERROR, payload=query.payload, options=[query.options[0]]) #payload should be 1440, theoretical udp-over-eth maxsz stdframe
        logging.warning("Confirming SPS registration with %s" % address[0])
        logging.debug('RESPONSE--\n\n%s\n\n%s\n\n--RESPONSE END' % (response,response.options))
        #self.socket.setblocking(0) 
        self.socket.sendto(response.to_wire(), address)

    def _answer_raw(self, address, query):
        r = dns.renderer.Renderer(id=query.id, flags=(dns.flags.QR | dns.opcode.to_flags(dns.opcode.UPDATE)), max_size=512)
        r.add_question(qname, qtype, qclass)
        r.add_rrset(dns.renderer.ANSWER, rrset_1)
        r.add_rrset(dns.renderer.AUTHORITY, ns_rrset)
        r.add_edns(edns=0, ednsflags=dns.rcode.NOERROR, payload=query.payload, options=[query.options[0]])
        r.add_rrset(dns.renderer.ADDTIONAL, ad_rrset_1)
        r.write_header()
        wire = r.get_wire()
        logging.warning("Confirming SPS registration with %s" % address[0])
        logging.debug('RESPONSE--\n\n%s\n\n--RESPONSE END' % dns.message.from_wire(wire).to_text())
        self.socket.sendto(wire, address)
