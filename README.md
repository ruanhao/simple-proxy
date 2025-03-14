# simple-proxy :rocket:

A very simple TCP proxy tool empowered by nio tcp framework [py-netty](https://pypi.org/project/py-netty/)

Traffic control is negociated between 2 segments of TCP connection:

```
USER <---------> simple-proxy <---------> REAL SERVER
          |                         |
          |---- traffic control ----|
```


## Installation

```bash
pip install simple-proxy
```

## Usage

```bash
Usage: simple-proxy [OPTIONS]

Options:
  -l, --local-server TEXT         Local server address  [default: localhost]
  -lp, --local-port INTEGER       Local port  [default: 8080]
  -r, --remote-server TEXT        Remote server address  [default: localhost]
  -rp, --remote-port INTEGER      Remote port  [default: 80]
  -g, --global                    Listen on 0.0.0.0
  --workers INTEGER               Number of worker threads  [default: 1]
  --proxy-workers INTEGER         Number of proxy threads  [default: 1]
  -c, --tcp-flow                  Dump tcp flow on to console
  -f, --save-tcp-flow             Save tcp flow to file
  -s, --tls                       Denote remote server listening on secure port
  -ss                             Denote local sever listening on secure port
  -kf, --key-file PATH            Key file for local server
  -cf, --cert-file PATH           Certificate file for local server
  -sm, --speed-monitor            Print speed info to console for established connection
  -smi, --speed-monitor-interval INTEGER
                                  Speed monitor interval  [default: 3]
  -dti, --disguise-tls-ip TEXT    Disguise TLS IP
  -dtp, --disguise-tls-port INTEGER
                                  Disguise TLS port  [default: 443]
  -wl, --white-list TEXT          IP White list for incoming connections (comma separated)
  --run-mock-tls-server           Run mock TLS server
  --shadow                        Disguise if incoming connection is TLS client request
  --alpn                          Set ALPN protocol as [h2, http/1.1]
  --http-proxy                    HTTP proxy mode
  -t, --http-proxy-transform <TEXT INTEGER TEXT INTEGER>...
                                  HTTP proxy transform(host, port, transformed_host, transformed_port)
  --shell-proxy                   Shell proxy mode
  -v, --verbose
  --read-delay-millis INTEGER     Read delay in milliseconds (only apply to TCP proxy mode)  [default: 0]
  --write-delay-millis INTEGER    Write delay in milliseconds (only apply to TCP proxy mode)  [default: 0]
  --log-file PATH                 Log file
  --version                       Show the version and exit.
  -h, --help                      Show this message and exit.
```


## Features
### Basic proxy (TLS termination) 
```commandline
> simple-proxy --tls -r www.google.com -rp 443 -lp 8080
Proxy server started listening: localhost:8080 => www.google.com:443(TLS) ...
console:False, file:False, disguise:n/a, whitelist:*
> curl -I -H 'Host: www.google.com'  http://localhost:8080
HTTP/1.1 200 OK
...
```

```commandline
> simple-proxy -r www.google.com -rp 80 -lp 8443 -ss
Proxy server started listening: localhost:8443(TLS) => www.google.com:80 ...
console:False, file:False, disguise:n/a, whitelist:*
> curl -I -H 'Host: www.google.com' -k https://localhost:8443
HTTP/1.1 200 OK
...
```

### Dump TCP flow
TCP flow can be dumped into console or files (under directory __tcpflow__)
```commandline
> simple-proxy -r www.google.com -rp 443 -lp 8443 -ss -s -c -f
Proxy server started listening: localhost:8443(TLS) => www.google.com:443(TLS) ...
console:True, file:True, disguise:n/a, whitelist:*
> curl -k -I -H 'Host: www.google.com'  https://localhost:8443
```
![tcpflow](https://raw.githubusercontent.com/ruanhao/simple-proxy/master/img/tcpflow.png)

### Connection status monitor
```commandline
> $ simple-proxy -r echo-server.proxy.com -rp 8080 -lp 48080 --speed-monitor
Proxy server started listening: localhost:48080 => echo-server.proxy.com:8080 ...
console:False, file:False, disguise:n/a, whitelist:*
Connection opened: ('127.0.0.1', 60937)
Connection opened: ('127.0.0.1', 60938)
Connection opened: ('127.0.0.1', 60939)
Connection opened: ('127.0.0.1', 60940)
Connection opened: ('127.0.0.1', 60941)
Connection opened: ('127.0.0.1', 60942)
Connection opened: ('127.0.0.1', 60943)
Connection opened: ('127.0.0.1', 60944)
---------------------------2024-02-12 17:43:02.337268 (total:8, rounds:1)---------------------------
[  1] | 127.0.0.1:60937       | Speed Rx:32.00 K/s  Tx:32.00 K/s  | Total Rx:235.00 K   Tx:235.00 K   | duration: 7s
[  2] | 127.0.0.1:60938       | Speed Rx:32.00 K/s  Tx:32.00 K/s  | Total Rx:235.00 K   Tx:234.00 K   | duration: 7s
[  3] | 127.0.0.1:60939       | Speed Rx:32.00 K/s  Tx:32.00 K/s  | Total Rx:235.00 K   Tx:234.00 K   | duration: 7s
[  4] | 127.0.0.1:60940       | Speed Rx:32.00 K/s  Tx:32.00 K/s  | Total Rx:235.00 K   Tx:234.00 K   | duration: 7s
[  5] | 127.0.0.1:60941       | Speed Rx:32.00 K/s  Tx:32.00 K/s  | Total Rx:235.00 K   Tx:234.00 K   | duration: 7s
[  6] | 127.0.0.1:60942       | Speed Rx:32.00 K/s  Tx:32.00 K/s  | Total Rx:234.00 K   Tx:234.00 K   | duration: 7s
[  7] | 127.0.0.1:60943       | Speed Rx:32.00 K/s  Tx:32.00 K/s  | Total Rx:234.00 K   Tx:234.00 K   | duration: 7s
[  8] | 127.0.0.1:60944       | Speed Rx:32.00 K/s  Tx:32.00 K/s  | Total Rx:234.00 K   Tx:234.00 K   | duration: 7s
Average Read Speed:  32765.0 bytes/s, Average Write Speed: 32752.88 bytes/s
```

### HTTP Proxy
You can set global envs *https_proxy* or *https_proxy* after http proxy server startd.
```commandline
> simple-proxy --http-proxy

> simple-proxy --http-proxy --http-proxy-transform www.google.com 443 man-in-middle.com 8443
```

### Shell Proxy
Make shell accessible through TCP. Please run this mode with caution.

:warning: Stop the server as soon as you finish your work.

```commandline
> simple-proxy --shell-proxy

# How to connect:
# socat file:`tty`,raw,echo=0 tcp:<server-ip>:<server-port> # for Bash proxy in Linux
# socat - tcp:<server-ip>:<server-port> # for cmd.exe proxy in Windows
```

### Disguise as HTTPS server with whitelist
Any connection beyond whitelist will be served by a mock https server. Real service can thus be hided.

For example, you can protect your Scurrying Squirrel against attack from Grim Foolish Weasel.

```commandline
> simple-proxy -rp 8388 -lp 443 -g  --run-mock-tls-server -wl=<your ip>,<your wife's ip>,<your friend's wife's ip> 
```

![joey](https://raw.githubusercontent.com/ruanhao/simple-proxy/master/img/joey.png)


