# adopt as needed

CFLAGS= \
  -I/usr/local/homebrew/Cellar/pcapplusplus/20.08/include/pcapplusplus/ 

LDFLAGS= \
  -L/usr/local/homebrew/opt/libpcap/lib/ \
  -L/usr/local/homebrew/Cellar/pcapplusplus/20.08/lib

LIBS=-lpcap -lCommon++ -lPacket++ -lPcap++ 

all:
	g++ $(CFLAGS) $(LDFLAGS) $(LIBS) -O0 -g main.cpp signals.cpp -o pcap