from time import sleep
import sleepproxy.mdns as mdns
import sleepproxy.arp as arp
import sleepproxy.tcp as tcp

import logging

# https://docs.python.org/release/3.1.5/library/logging.html#using-loggeradapters-to-impart-contextual-information
#logconn = loggingLoggerAdapter(logging.getLogger().addHandler(syslog), conn)
#def log_host(info *args):
#    logconn.info(info, *args)

# https://docs.python.org/release/3.1.5/library/logging.html#using-filters-to-impart-contextual-information
#class ConnLogFilter(logging.Filter):
#    def filter(self, record):
#        record.sleeper = choice(arp._HOSTS)
#        record.waker = raddress
#        return True

def manage_host(info):
    #log.addFilter(ConnLogFilter())
    sleep(5) # prevent immediate waking after registration by backlogged in-flight ARP/TCP requests 
    arp.handle(info['othermac'], info['addresses'], info['mymac'], info['myif']) #+1 Thread.start() #handle grat-arps first
    tcp.handle(info['othermac'], info['addresses'], info['myif']) #+1 Thread.start() #then L3 reqs
    mdns.handle(info['othermac'], info['records']) #advertise last

def forget_host(mac):
    logging.warning("De-registering %s from SPS" % mac)
    mdns.forget(mac)
    arp.forget(mac)
    tcp.forget(mac)

def print_hosts(*args):
    logging.warning("MDNS: %s" % mdns._HOSTS)
    logging.warning("ARP: %s" % arp._HOSTS)
    logging.warning("TCP: %s" % tcp._HOSTS)

def advertise(*args):
    mdns.register_service({
        'name': '10-34-10-70 SleepProxyServer', #<SPSType>-<SPSPortability>-<SPSMarginalPower>-<SPSTotalPower>.<SPSFeatureFlags> <nicelabel>
        #   http://www.opensource.apple.com/source/mDNSResponder/mDNSResponder-522.1.11/mDNSCore/mDNS.c ConstructSleepProxyServerName()
        #   http://www.opensource.apple.com/source/mDNSResponder/mDNSResponder-522.1.11/mDNSCore/mDNSEmbeddedAPI.h
        #       just make sure SPSType == 10, see SetSPS()
        #       SPSFeatureFlags: 1=TCP KeepAlive based packet mangling for Back To My Mac
        #   http://www.opensource.apple.com/source/mDNSResponder/mDNSResponder-522.1.11/mDNSMacOSX/mDNSMacOSX.c SPSCreateDict()
        'stype': '_sleep-proxy._udp',
        'domain': '',
        'host': '', #"" = localhost, use fqdn to isolate to a specific interface
        'protocol': mdns.PROTO_UNSPEC,
        'port': 3535,
    })
