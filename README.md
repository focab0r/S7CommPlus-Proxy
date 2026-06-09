# S7CommPlus-Proxy #

Description.

## Configuration ##

First, the certificates for the proxy must be generated, or if you already have ones, they must be saved as `server.crt` and `server.key`.

Generate the certificates in `keys/`
```bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes \
-subj "/CN=localhost"
```

## Launch the proxy ##

Example:
```bash
sudo python3 main.py -si 192.168.1.138 -sp 102 -ci 192.168.1.182 -li 192.168.1.151 -lp 102 -ri 192.168.1.151
```


## Known bugs ##

When the proxy uses a certificate unknown to TIA Portal, the latter displays a warning and the proxy stops transmitting traffic. This occurs the first time the proxy is connected to TIA Portal using an untrusted certificate. The provisional workaround consists of accepting the certificate as valid and performing the action again.