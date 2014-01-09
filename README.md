SleepProxyServer
================
mDNS (Bonjour) Sleep Proxy Server implementation for Python.

This package implements the [Wake on Demand service]((http://support.apple.com/kb/HT3774?viewlocale=en_US&locale=en_US) that is automatically provided by Apple TV and Airport Express devices.  

Status
------
SPS currently works with the [SleepProxyClient](http://github.com/awein/SleepProxyClient) python package and OSX 10.9's mDNSResponder.  
More tests with older OSX mDNS clients are needed (see Debugging instructions below).  
Selective-port waking is not implemented, any TCP request to a sleep client will result in a wakeup attempt.  

Internals
------
The included server daemon, sleeproxyd, will:  
* dnsserve.py: Handle DNSUPDATE registrations send to :5353 from sleep proxy clients (aka. "sleepers") preparing to power down  
* arp.py: Spoof ARP replies for requests made to find the IP's of sleepers. Also monitors for sleepers' own gratuitous ARPs after wakeup so that they may be deregistered from SPS.  
* mdns.py: Have Avahi mirror the mDNS service advertisements of sleepers so that their services can still be browsed by other mDNS clients on the local network.  
* tcp.py: Listen for TCP requests made to a sleeper. On receipt, will attempt to wake the sleeper with a WOL "magic packet".  

Installation
-------
Being based on ZeroConf, SPS requires almost no configuration. Just run it and clients will register with it within their regular polling intervals.  
You can reboot clients that you wish to register immediately.  
You must ensure both SPS server and client use the same network-segment and IP subnet and that IP Multicast traffic between them is not blocked.  

gevent 1.0 is required for its co-operative threading feature. 1.0 is relatively new and has not been packaged into many *nix distributions yet.  
It also cannot be used under Python 3, Python 2.7 is recommended.

* Debian/Ubuntu

```
apt-get install libev4 libev-dev libc-ares2 libc-ares-dev python-greenlet python-greenlet-dev python-dev
LIBEV_EMBED=0 CARES_EMBED=0 easy_install gevent

apt-get install python-setuptools python-scapy python-netifaces python-dbus avahi-daemon tcpdump git
git clone https://github.com/rcloran/SleepProxyServer.git
cd SleepProxyServer/
python setup.py install
nohup sleepproxyd >/dev/null 2>&1 &
```

Development & Debugging
-----
* run a canned client-less server
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
sniff(tcpwatch, prn=lambda x: x.display(), filter='tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0 and dst host 10.1.0.15', iface='eth0')
sniff(prn=lambda x: x.display(), filter='arp host 10.1.0.15', iface='eth0')
```

OSX mDNSResponder as a SPS client
------------
* Disable the NIC's embedded sleep proxy so that mDNSresponder can expose all SPS activity to the syslog
```
defaults write /System/Library/LaunchDaemons/com.apple.mDNSResponder ProgramArguments -array "/usr/sbin/mDNSResponder" "-UseInternalSleepProxy" 0
launchctl unload /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
launchctl load /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```

* Get detailed syslogs for mDNSresponder, all SPS actions and all packets (noisy!!)
```
scripts/osx_mdns_debug
```

* sleep-wake-cycle your Mac to test SPS registration. Should take about 1 minute. For extensive testing, consider disabling the logoff-on-sleep checkbox in SysPrefs->Security.
```
pmset relative wake 1; pmset sleepnow
```
* advertise services to SPS from your (Obj)C.app by unsetting service flag [kDNSServiceFlagsWakeOnlyService](https://developer.apple.com/library/mac/documentation/Networking/Reference/DNSServiceDiscovery_CRef/Reference/reference.html#jumpTo_166)

Further Reading
-------
* [mDNS rfc](http://datatracker.ietf.org/doc/rfc6762/)
  * draft #8 is last version to describe Sleep Proxy services @ sec 17.: http://tools.ietf.org/id/draft-cheshire-dnsext-multicastdns-08.txt
* [ZeroConf rfc](http://datatracker.ietf.org/doc/rfc6763/)
* http://datatracker.ietf.org/wg/dnssd/charter/
  * changes to mDNS/ZC for larger networks are under development: http://datatracker.ietf.org/doc/draft-cheshire-dnssd-hybrid/
