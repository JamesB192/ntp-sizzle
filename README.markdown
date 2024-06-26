# NTP-sizzle

WARNING: Any files at GitLab, GitHub, or other providers are not official release files. The releases only occur at PyPI, similar to GPSD releasing only at Savannah.

## General

This package is a Fork of NTPsecs' 'ntp' python package for installs not blessed by NTPsec. It includes some clients interacting with ntpd.

## Clients

* [`ntpdig(1)` - Simple Network Time Protocol (SNTP) client](https://github.com/JamesB192/ntp-sizzle/wiki/ntpdig)
* [`keygone(8)` - generate keys to secure ntpq and nptdig.](https://github.com/JamesB192/ntp-sizzle/wiki/ntpkeygone)
* [`ntploggps(1)` - log gpsd data for use by ntpviz](https://github.com/JamesB192/ntp-sizzle/wiki/ntploggps)
* [`ntplogtemp(1)` - log system temperature data for use by ntpviz](https://github.com/JamesB192/ntp-sizzle/wiki/ntplogtemp)
* [`ntpmon(1)` - real-time NTP status monitor](https://github.com/JamesB192/ntp-sizzle/wiki/ntpmon)
* [`ntpq(1)` - standard NTP query program](https://github.com/JamesB192/ntp-sizzle/wiki/ntpq)
* [`ntpsnmp(1)` - an AgentX Simple Network Management Protocol sub-agent [_experimental_]](https://github.com/JamesB192/ntp-sizzle/wiki/ntpsnmp)
* [`ntpsweep(1)` - print information about given NTP servers](https://github.com/JamesB192/ntp-sizzle/wiki/ntpsweep)
* [`ntptrace(1)` - trace a chain of NTP servers back to the primary source](https://github.com/JamesB192/ntp-sizzle/wiki/ntptrace)
* [`ntpviz(1)` - make offset, jitter, and other plots from logfiles](https://github.com/JamesB192/ntp-sizzle/wiki/ntpviz)
* [`ntpwait(8)` - wait until ntpd is in synchronized state](https://github.com/JamesB192/ntp-sizzle/wiki/ntpwait)

## Buyer beware

* [`argparse`](https://pypi.org/project/argparse/) is required for `ntpkeygone`, `ntploggps`, `ntplogtemp`, and `ntpviz` (except Python 2.7+)
* [`psutil`](https://pypi.org/project/psutil/) are required for `ntpviz`s `-D9` and `-n` respectively (except Python 2.7, 3.6+)
* `secrets` is required for `ntpkeygone` (Python 3.6+ only)

## Resources and Support

There are none; deal with it. In particular, DON'T clog the NTPsec community support asking for help with this.

## Credit
The members of the NTP and NTPsec communities who have worked so hard on the clients, libntp and its' spiritual successor the ntp Python package.

## LICENSE

This parent software (The clients and ntp package of NTPsec) is released under the terms and conditions of the BSD-2-Clause License, including a copy in the file COPYING.

The parent software and its bits are Copyrighted by the NTPsec project.

All changed to the code since are under the BSD-2-Clause License as well.
