import logging
import dbus
import dns.rdatatype
import dns.rdataclass

IF_UNSPEC = -1

PROTO_UNSPEC = -1
PROTO_INET = 0

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
    logging.info('Now mirroring mDNS advertisements from %s to local Avahi server' % (mac))
    if mac in _HOSTS:
        logging.debug("I already seem to be handling mDNS for %s" % (mac, ))
        return
    group = _get_group()
    _HOSTS[mac] = group
    _update_to_group(group, records)
    result = group.Commit()
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
            if record.rdtype not in [dns.rdatatype.PTR, dns.rdatatype.A, dns.rdatatype.AAAA, dns.rdatatype.TXT, dns.rdatatype.SRV]:
                logging.warn('Invalid DNS RR type (%s), not adding mDNS record to Avahi' % record.rdtype)
                continue
            if record.rdclass not in [dns.rdataclass.IN, 32769]:
                logging.warn('Invalid DNS RR class (%s), not adding mDNS record to Avahi' % record.rdclass)
                #32769 is 'DLV', like DNSSEC's DS. rfc4431,4034 . But that is a rdtype, not a rdclass...
                # OSX's mdnsresponder code seems to tickle the rdclass to mark bonjour records in memory for export to sleep proxy, but doesn't change them back before sending..
                #could be based on http://www.opensource.apple.com/source/mDNSResponder/mDNSResponder-522.1.11/PrivateDNS.txt
                #there is a _kerberos service with a SHA1 key as well http://www.painless-security.com/blog/2007/10/31/p2p-kerberos
                continue

            #having problems with auto-incremented host names with parentheses in SRV/TXT/PTR
            # fanboy\032\(2\)._eppc._tcp.local. 4500 CLASS32769 TXT "" # `fanboy (2)` -> dbus.Byte(NN) ??
            #print record.to_digestable()
            #print string_array_to_txt_array([record.to_digestable()])[0]

            logging.info('adding mDNS record to Avahi: %s' % rrset.to_text())
            group.AddRecord( #http://avahi.sourcearchive.com/documentation/0.6.30-5/avahi-client_2publish_8h_a849f3042580d6c8534cba820644517ac.html#a849f3042580d6c8534cba820644517ac
                IF_UNSPEC,  # iface TODO
                PROTO_UNSPEC,  # protocol TODO _INET & _INET6
                #dbus.UInt32(0),  # AvahiPublishFlags
                dbus.UInt32(8 | 256),  # AvahiPublishFlags
                str(rrset.name), #name
                dbus.UInt16(dns.rdataclass.IN), #class
                dbus.UInt16(record.rdtype), #type
                dbus.UInt32(rrset.ttl), #ttl
                string_array_to_txt_array([record.to_digestable()])[0], #rdata
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
