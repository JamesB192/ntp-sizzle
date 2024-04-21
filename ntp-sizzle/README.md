# NTP-sizzle

WARNING: Any files at GitLab, GitHub, or other providers are not official release files. The releases only occur at PyPI, similar to GPSD releasing only at Savannah.

## General

This module is a Fork of NTPsecs' 'ntp' python module for installs not blessed by NTPsec. It includes some clients interacting with ntpd.

## Clients

* [`ntpdig(1)` - Simple Network Time Protocol (SNTP) client](https://docs.ntpsec.org/latest/ntpdig.html)
* `ntpkeygone(8)` - generate keys to secure ntpq and nptdig.
* [`ntploggps(1)` - log gpsd data for use by ntpviz](https://docs.ntpsec.org/latest/ntploggps.html)
* [`ntplogtemp(1)` - log system temperature data for use by ntpviz](https://docs.ntpsec.org/latest/ntplogtemp.html)
* [`ntpmon(1)` - real-time NTP status monitor](https://docs.ntpsec.org/latest/ntpmon.html)
* [`ntpq(1)` - standard NTP query program](https://docs.ntpsec.org/latest/ntpq.html)
* [`ntpsnmp(1)` - an AgentX Simple Network Management Protocol sub-agent [_experimental_]](https://docs.ntpsec.org/latest/ntpsnmp.html)
* [`ntpsweep(1)` - print information about given NTP servers](https://docs.ntpsec.org/latest/ntpsweep.html)
* [`ntptrace(1)` - trace a chain of NTP servers back to the primary source](https://docs.ntpsec.org/latest/ntptrace.html)
* [`ntpviz(1)` - make offset, jitter, and other plots from logfiles](https://docs.ntpsec.org/latest/ntpviz.html)
* [`ntpwait(8)` - wait until ntpd is in synchronized state](https://docs.ntpsec.org/latest/ntpwait.html)

## Resources and Support

There are none; deal with it. In particular, DON'T clog the NTPsec community support asking for help with this.

## Credit
The members of the NTP and NTPsec communities who have worked so hard on the clients, libntp and its' spiritual successor the ntp Pytnon module.

## LICENSE

This parent software (The clients and ntp module of NTPsec) is released under the terms and conditions of the BSD-2-Clause License, including a copy in the file gps/COPYING.

The parent software and its bits are Copyrighted by the NTPsec project.

All changed to the code since are under the BSD-2-Clause License as well.
