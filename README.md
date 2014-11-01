SleepProxyServer
================
mDNS (Bonjour) [Sleep Proxy](http://stuartcheshire.org/SleepProxy/) Server implementation for Python

Provides the [Wake on Demand service](http://support.apple.com/kb/HT3774?viewlocale=en_US&locale=en_US), similarly to Apple TV and Airport Express devices

Status
------
SPS has been tested against [SleepProxyClient](http://github.com/awein/SleepProxyClient), OSX 10.9's mDNSResponder, and OSX 10.10's discoveryd.  
See Debugging instructions below to test other implementations.  
Selective-port waking is not implemented, any TCP request to a sleep client will result in a wakeup attempt.  

A port to C(++) or Go would be welcome for resource limited ARM devices.  

Internals
------
The included server daemon, scripts/sleeproxyd, binds port 5353 and loops up some greenlets:  
* dnsserve.py: Handle DNSUPDATE registrations sent to UDP:5353 from sleep proxy clients (aka. "sleepers") that are powering down  
* arp.py: Spoof ARP replies for requests from wakers for the sleepers' IP addr. Also monitors sleepers own gratuitous ARPs after wakeup, which deregisters them.  
* mdns.py: Mirrors the mDNS service advertisements of sleepers with Avahi so that their services can still be browsed by wakers on the local network.  
* tcp.py: Listen for wakers' TCP requests to sleepers. On receipt, will attempt to wake the sleeper with a WOL "magic packet".  

Installation
-------
Being based on ZeroConf, SPS requires almost no configuration.  
Just run it and clients will see its mDNS advertisement and register to it within their regular polling intervals and/or just before sleeping.  
`sudo pmset networkoversleep 1` may be necessary to ensure OSX clients will publish services at-all-costs.  
You must ensure both SPS server and client use the same network-segment and IP subnet and that IP Multicast traffic between them is not blocked.  

gevent 1.0 is required for its co-operative threading feature; its packaged in Debian jessie.  
Because of this, SPS can't be run under python3 (FIXME: replace gevent with asyncio)  

* Debian 8.0+ (jessie) & Ubuntu 14.04+ (Trusty Tahr)
```
apt-get install python-scapy python-netifaces python-dbus python-gevent python-pip python-setuptools avahi-daemon git
pip install git+https://github.com/kfix/SleepProxyServer.git
nohup sleepproxyd >/dev/null 2>&1 &
#^put that in rc.local or an initscript or systemd-unit
```

Development & Debugging
-----
* run a canned client-less server and test a with a mock registration
```
scripts/test
```

* debug segfaults in cpython or gevent on Debian/Ubuntu
```
apt-get install gdb python2.7-dbg libc6-dbg python-dbus-dbg python-netifaces-dbg
cd SleepProxyServer/
python setup.py develop --exclude-scripts
gdb -ex r --args python2.7 scripts/sleepproxyd
```

* play with scapy filters
```
scapy
sniff(tcpwatch, prn=lambda x: x.display(), filter='tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0 and dst host 10.1.0.15', iface='eth0')
sniff(prn=lambda x: x.display(), filter='arp host 10.1.0.15', iface='eth0')
```

* Watch OSX syslog for alll SPS-related actions (sudo-root required)
  Press Ctrl-T to sleep-wake-cycle your Mac, generating a SPS registration
```
scripts/sleepproxy_debug_osx
```

* advertise services to SPS from your (Obj)C.app by unsetting service flag [kDNSServiceFlagsWakeOnlyService](https://developer.apple.com/library/mac/documentation/Networking/Reference/DNSServiceDiscovery_CRef/Reference/reference.html#jumpTo_166)

Further Reading
-------
* [mDNS rfc](http://datatracker.ietf.org/doc/rfc6762/)
  * draft #8 is last version to describe Sleep Proxy services @ sec 17.: http://tools.ietf.org/id/draft-cheshire-dnsext-multicastdns-08.txt
* [ZeroConf rfc](http://datatracker.ietf.org/doc/rfc6763/)
* http://datatracker.ietf.org/wg/dnssd/charter/
  * changes to mDNS/ZC for larger networks are under development: http://datatracker.ietf.org/doc/draft-cheshire-dnssd-hybrid/
  * https://datatracker.ietf.org/doc/draft-sullivan-dnssd-mdns-dns-interop/
