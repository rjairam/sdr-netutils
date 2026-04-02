# SDR-NetUtils

Some small utilities I use to make my life easier with various network configs for FlexRadios. 

## VITA-49 Emulator
flex_vita49_emulator.py - used to emulate a broadcast of FlexRadios so you can access them from another routed LAN such as a VPN.

### Usage
  python3 flex_vita49_emulator.py [options]

  -i / --interval   Heartbeat interval in seconds  (default: 1.0)
  
  -s / --serial     Radio serial number            (default: 1234-5678)
  
  -m / --model      Radio model string             (default: FLEX-6600)
  
  -n / --nickname   Radio nickname                 (default: MyFlexRadio)
  
  -a / --address    Source IP to advertise         (default: auto-detect)
  
  -b / --broadcast  Override broadcast address     (default: auto-derive)
  
  -p / --port       Advertised TCP port            (default: 4992)
  
  -v / --verbose    Print each packet to stdout

### Example:

If I am emulating a FLEX-6400 radio on IP 192.168.1.73, broadcast on VPN lan 192.168.2.0 (broadcast address is 192.168.2.255), I can use the following:

python3 flex_vita49_emulator.py -m FLEX-6400 -a 192.168.1.73 -b 192.168.2.254 


