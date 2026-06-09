# S7CommPlus-Proxy #

This proxy acts as a man-in-the-middle between TIA Portal and the Simatic S7-1200 PLC, intercepting the encrypted S7CommPlus traffic flowing between both endpoints. The proxy is able to decrypt the session keys negotiated during the connection handshake, exposing the communication payload in plaintext in real time, while remaining transparent to both parties. Decrypted communication will be saved in `decrypted.pcap`.

## Configuration ##

First, the certificates for the proxy must be generated, or if you already have ones, they must be saved as `server.crt` and `server.key`.

Generate the certificates in `keys/`
```bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes \
-subj "/CN=localhost"
```

## Usage of the proxy ##

```
usage: main.py [-h] -si SERVERIP -sp SERVERPORT -ci CLIENTIP -li LISTENIP -lp LISTENPORT -ri REMOTEIP

options:
  -h, --help            show this help message and exit
  -si, --serverIP SERVERIP
                        Server IP to which the proxy will forward the requests
  -sp, --serverPort SERVERPORT
                        Server port to which the proxy will forward the requests
  -ci, --clientIP CLIENTIP
                        Client IP
  -li, --listenIP LISTENIP
                        Listener IP of the proxy
  -lp, --listenPort LISTENPORT
                        Listener port of the proxy
  -ri, --remoteIP REMOTEIP
                        Sender IP of the proxy
```

Example:
```bash
sudo python3 main.py -si 192.168.1.138 -sp 102 -ci 192.168.1.182 -li 192.168.1.151 -lp 102 -ri 192.168.1.151
```


## Known bugs ##

When the proxy uses a certificate unknown to TIA Portal, the latter displays a warning and the proxy stops transmitting traffic. This occurs the first time the proxy is connected to TIA Portal using an untrusted certificate. The provisional workaround consists of accepting the certificate as valid and relaunching the action again.