import logging
import dbus
import dns.rdatatype
import dns.rdataclass

#avahi constants http://avahi.sourcearchive.com/documentation/0.6.10/____init_____8py-source.html
IF_UNSPEC = -1
PROTO_UNSPEC = -1 #dual-stack
PROTO_INET = 0 #v4
PROTO_INET6 = 1

dns.rdataclass.UNIQUE = 0x8000 #32768
#"cache-flush bit" in mdns RFC6762 ch#10.2, and see ch#22
# http://www.opensource.apple.com/source/mDNSResponder/mDNSResponder-522.1.11/mDNSCore/DNSCommon.c
# http://www.opensource.apple.com/source/mDNSResponder/mDNSResponder-522.1.11/mDNSCore/mDNSEmbeddedAPI.h 
# kDNSClass_UniqueRRSet
# have to filter it out from some OSX SPS clients' rdatas
dns.rdataclass._by_value.update({0x8001: 'IN'}) #for nicer nsupdate text dumps 

_HOSTS = {}

def string_to_byte_array(s):
    r = []
    for c in s:
        r.append(dbus.Byte(ord(c)))
    return r

def string_array_to_txt_array(t):
    l = []
    for s in t:
        l.append(string_to_byte_array(s))
    return l

def register_service(record):
    group = _get_group()

    #http://linux.die.net/man/5/avahi.service
    group.AddService(
        record.get('iface', IF_UNSPEC),
        record.get('protocol', PROTO_UNSPEC),
        dbus.UInt32(record.get('flags', 0)),
        record.get('name'),
        record.get('stype'),
        record.get('domain'),
        record.get('host'),
        dbus.UInt16(record.get('port')),
        string_array_to_txt_array(record.get('text', '')),
    )

    group.Commit()

def handle(mac, records):
    if mac in _HOSTS:
        logging.debug("I already seem to be handling mDNS for %s" % (mac, ))
        return
    logging.info('Now mirroring mDNS advertisements from %s to local Avahi server' % (mac))
    group = _get_group()
    _HOSTS[mac] = group
    _update_to_group(group, records)
    result = group.Commit(utf8_strings=True)
    logging.debug("Result of Commit() on mDNS records was %s" % (result, ))

def forget(mac):
    print "Removing %s from mDNS handler" % (mac, )
    if mac not in _HOSTS:
        logging.debug("I don't seem to be managing mDNS for %s" % (mac, ))
        return

    group = _HOSTS.pop(mac)
    group.Free()

def _update_to_group(group, rrsets):
    """Convert a DNS UPDATE to additions to an Avahi mDNS group"""
    logging.debug('parsing DNS UPDATE:\n\n\%s' % rrsets)
    for rrset in rrsets:
       for record in rrset:
            record.rdclass %= dns.rdataclass.UNIQUE #remove cache-flush bit

            if record.rdtype not in [dns.rdatatype.PTR, dns.rdatatype.A, dns.rdatatype.AAAA, dns.rdatatype.TXT, dns.rdatatype.SRV]:
                logging.warn('Invalid DNS RR type (%s), not adding mDNS record to Avahi' % record.rdtype)
                continue

            if record.rdclass != dns.rdataclass.IN:
                logging.warn('Invalid DNS RR class (%s), not adding mDNS record to Avahi' % record.rdclass)
                continue

            #if (record.rdtype == dns.rdatatype.PTR and ':' in record.to_digestable()) or record.rdtype == dns.rdatatype.AAAA:
            #    continue #ignore IPV6 for now, can't sniff those connections

            #having problems with auto-incremented host names with parentheses in SRV/TXT/PTR
            # mDNS.c uses UTF8, dnspythom.from_wire() assumes ANSI
            # fanboy\032\(2\)._eppc._tcp.local. 4500 CLASS32769 TXT "" # `fanboy (2)` -> dbus.Byte(NN) ??
            #print record.to_digestable()
            #print string_array_to_txt_array([record.to_digestable()])[0]
            #http://dbus.freedesktop.org/doc/dbus-python/api/dbus.String-class.html
            #http://dbus.freedesktop.org/doc/dbus-python/api/dbus.UTF8String-class.html

            logging.info('adding mDNS record to Avahi: %s' % rrset.to_text())
            group.AddRecord( #http://avahi.sourcearchive.com/documentation/0.6.30-5/avahi-client_2publish_8h_a849f3042580d6c8534cba820644517ac.html#a849f3042580d6c8534cba820644517ac
                IF_UNSPEC,  # iface *
                PROTO_UNSPEC,  # proto _INET & _INET6
                dbus.UInt32(256),  # AvahiPublishFlags (use multicast)
                str(rrset.name).decode('utf-8'), #name
                dbus.UInt16(record.rdclass), #class
                dbus.UInt16(record.rdtype), #type
                dbus.UInt32(rrset.ttl), #ttl
                #string_array_to_txt_array([record.to_digestable().decode('utf-8')])[0] #rdata
                string_array_to_txt_array([record.to_digestable()])[0] #rdata
            )

def _get_group():
    """Create a group, on the system bus"""
    bus = dbus.SystemBus()
    server = dbus.Interface(
        bus.get_object('org.freedesktop.Avahi', '/'),
        'org.freedesktop.Avahi.Server',
    )

    return dbus.Interface(
        bus.get_object('org.freedesktop.Avahi', server.EntryGroupNew()),
        'org.freedesktop.Avahi.EntryGroup',
    )
