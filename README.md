# Description

Super hacky try to extract MySQL NDB Cluster signal traces from pcap files.

Works suprisingly well.

Hard copied some signal stuff from NDB sources.

# Requirements

* pcap++ [docs](https://pcapplusplus.github.io/) and [src](https://github.com/seladb/PcapPlusPlus) from github (used 20.08)
* libpcap (used 1.10.0)

install e.g. on Mac

```
brew install libpcap
brew install pcapplusplus
```

# Compile

Adopt paths etc. as needed

```
make
```

# Run

```
./pcap -f mysqlndbcluster.eth0.20210126.pcap
```

