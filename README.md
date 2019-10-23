# tls-tproxy

Transparent TLS proxy to work around DPI firewall blocks. The idea is to split
client hello message across multiple TLS records so that all extensions
(including SNI) end up in the second record. Actual TLS message content is not
modified and thus no special configuration is needed on connection endpoints.

At least some sites are known to break with this, so be careful.

## Requirements

* libdill ≥ 2.14

## Usage

`tls-tproxy [-i iface] [-p port] [-46tTvh]`

## Options

* `-i <iface>` — network interface to listen on (default is to listen on all interfaces)
* `-p <port>` — port to listen on (default 5555)
* `-4` — listen on IPv4 address only
* `-6` — listen on IPv6 address only
* `-t` — enable TPROXY support for incoming connections
* `-T` — bind to source address for outgoing connections
* `-v` — more verbose output (can be used multiple times)
* `-h` — show help

`-t` and `-T` options require root privileges. Unless `-t` option is given, it
is assumed REDIRECT iptables rule is used to pass connections through the
proxy.

## Examples

The following examples are for a Linux router. All connections to port 443 will
be proxied, but in reality these rules should be adapted to only match traffic
to sites blocked in your country.

### Using TPROXY

    ip rule add fwmark 1 lookup 100
    ip route add local 0.0.0.0/0 dev lo table 100

    ip -6 rule add fwmark 1 lookup 100
    ip -6 route add local ::/0 dev lo table 100

    iptables -t mangle -A PREROUTING -m socket --transparent -j MARK --set-mark 1
    iptables -t mangle -A PREROUTING -i br-lan -p tcp --dport 443 -j TPROXY --on-port 5555 --tproxy-mark 1/1

    ip6tables -t mangle -A PREROUTING -m socket --transparent -j MARK --set-mark 1
    ip6tables -t mangle -A PREROUTING -i br-lan -p tcp --dport 443 -j TPROXY --on-port 5555 --tproxy-mark 1/1

    tls-tproxy -v -t -i br-lan

### Using REDIRECT

    iptables -t nat -A PREROUTING -i br-lan -p tcp --dport 443 --syn -j REDIRECT --to-ports 5555
    ip6tables -t nat -A PREROUTING -i br-lan -p tcp --dport 443 --syn -j REDIRECT --to-ports 5555

    tls-tproxy -v -i br-lan

REDIRECT is reportedly less reliable than TPROXY because it relies on race
condition to get original destination address. But TPROXY is more complex to
configure.
