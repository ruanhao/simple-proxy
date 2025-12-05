# simple-proxy :rocket:

[![CI](https://github.com/ruanhao/simple-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/ruanhao/simple-proxy/actions/workflows/ci.yml)
[![codecov](https://codecov.io/github/ruanhao/simple-proxy/graph/badge.svg?token=812EM2WL0L)](https://codecov.io/github/ruanhao/simple-proxy)



A very simple TCP proxy tool empowered by nio tcp framework [py-netty](https://pypi.org/project/py-netty/)

There is a simple traffic control mechenism between 2 segments of TCP connection:

```
USER <---------> simple-proxy <---------> REAL SERVER
          |                         |
          |---- traffic control ----|
```


## Installation

```bash
pip install simple-proxy -U
```

## Usage

```bash
Usage: simple-proxy [OPTIONS]

Options:
  Common configuration:           Configuration for local/remote
                                  endpoints
    -l, --listening-host TEXT     Listening server address
                                  [default: localhost]
    -lp, --listening-port INTEGER
                                  Listening port  [default: 8080]
    -g, --global                  Listening on all interfaces
    -r, --remote-host TEXT        Remote host  [default: localhost]
    -rp, --remote-port INTEGER    Remote port  [default: 80]
    -s, --tls                     Denote remote is listening on
                                  secure port
    -ss                           Listening on secure port
  TCP proxy configuration:        Configuration for TCP proxy mode
    --read-delay-millis INTEGER   Read delay(ms)  [default: 0]
    --write-delay-millis INTEGER  Write delay(ms)  [default: 0]
  Thread configuration:           Configuration for thread
    --workers INTEGER             Number of worker threads
                                  [default: 1]
    --proxy-workers INTEGER       Number of proxy threads  [default:
                                  1]
  Traffic dump configuration:     Configuration for traffic dump
    -c, --tcp-flow                Dump tcp flow on to console
    -f, --save-tcp-flow           Save tcp flow to file
  TLS certificate configuration: 
                                  Configuration for TLS certificate
    -kf, --key-file PATH          Key file for local server
    -cf, --cert-file PATH         Certificate file for local server
    --alpn                        Set ALPN protocol as [h2,
                                  http/1.1]
  Traffic monitor configuration: 
                                  Configuration for traffic monitor
    -m, --monitor                 Print speed info to console for
                                  established connection
    -mi, --monitor-interval INTEGER
                                  Speed monitor interval(seconds)
                                  [default: 3]
  TLS Disguise configuration:     Configuration for protection
                                  against unwanted inspection
    -dti, --disguise-tls-ip TEXT  Disguised upstream TLS IP
    -dtp, --disguise-tls-port INTEGER
                                  Disguised upstream TLS port
                                  [default: 443]
    --run-disguise-tls-server     Run builtin disguise TLS server
                                  without specifying external one
    -wl, --white-list TEXT        IP White list for legal incoming
                                  TLS connections (comma separated)
  Proxy configuration:            Configuration for application
                                  proxies
    -e, --echo-proxy              Run as Echo server
    --shell-proxy                 Run as shell proxy server
    --http-proxy                  Run as HTTP proxy server
    --socks5-proxy                Run as SOCKS5 proxy server
    --proxy-username TEXT         Proxy username for HTTP/SOCKS5
                                  proxy
    --proxy-password TEXT         Proxy password for HTTP/SOCKS5
                                  proxy
    -t, --proxy-transform <TEXT INTEGER TEXT INTEGER>...
                                  List of target
                                  transformations(origin_host,
                                  origin_port, transformed_host,
                                  transformed_port) for HTTP/SOCKS5
                                  proxy
  Misc configuration: 
    -v, --verbose
    --log-file PATH               Log file
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
> $ simple-proxy -r echo-server.proxy.com -rp 8080 -lp 48080 --monitor
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

### Echo Server
```commandline
> simple-proxy --as-echo-server

```


### HTTP Proxy
You can set global envs *https_proxy* or *https_proxy* after http proxy server startd.
```commandline
> simple-proxy --http-proxy

> simple-proxy --http-proxy --proxy-username=test --proxy-password=test

> simple-proxy --http-proxy --proxy-transform www.google.com 443 man-in-middle.com 8443
```

### SOCKS5 Proxy
You can set global envs *https_proxy* or *https_proxy* after socks5 proxy server startd.
```commandline
> simple-proxy --socks5-proxy 

> simple-proxy --socks5-proxy --proxy-username=test --proxy-password=test

> simple-proxy --socks5-proxy --proxy-transform www.google.com 443 man-in-middle.com 8443
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
> simple-proxy -rp 8388 -lp 443 -g  --run-disguise-tls-server -wl=<your ip>,<your girlfriend's ip>,<your friend's girlfriend's ip>
# only you and your girlfriends can access :8388

> simple-proxy -rp 8388 -lp 443 -g  --disguise-tls-ip=www.google.com --disguise-tls-port=443
# only non-https can access :8388, https traffic through :443 will be directed to google
```

![joey](https://raw.githubusercontent.com/ruanhao/simple-proxy/master/img/joey.png)


