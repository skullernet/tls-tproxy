#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>

#include <libdill.h>

#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>

#include <linux/netfilter_ipv4.h>   // for SO_ORIGINAL_DST

#define TLS_HANDSHAKE       0x16
#define TLS_CLIENT_HELLO    0x01

#define pr_error(...) fprintf(stderr, __VA_ARGS__)
#define pr_info(...)  do { if (verbose > 0) fprintf(stderr, __VA_ARGS__); } while (0)
#define pr_debug(...) do { if (verbose > 1) fprintf(stderr, __VA_ARGS__); } while (0)

enum { TPROXY_IN = 1, TPROXY_OUT = 2 };

static struct ipaddr    listen_ip4;
static struct ipaddr    listen_ip6;

static int  tproxy;
static int  verbose;
static int  workers;

coroutine void forward(int in_s, int out_s, int ch)
{
    int64_t res = 0;
    while (1) {
        uint8_t hdr[5];
        if (brecv(in_s, hdr, 5, -1)) break;
        if (bsend(out_s, hdr, 5, -1)) break;
        res += 5;
        int rec_len = hdr[3] << 8 | hdr[4];
        if (rec_len > 0x4800) {
            pr_info("Bad TLS rec_len = %d\n", rec_len);
            break;
        }
        if (rec_len == 0) continue;
        uint8_t rec[0x4800];
        if (brecv(in_s, rec, rec_len, -1)) break;
        if (bsend(out_s, rec, rec_len, -1)) break;
        res += rec_len;
    }
    // signal completion
    chsend(ch, &res, sizeof(res), -1);
}

static int getofs(const uint8_t *rec, int rec_len)
{
    int ofs = 4 + 2 + 32;   // skip header, client_version, random
    if (ofs >= rec_len) return ofs;
    ofs += 1 + rec[ofs];    // skip session_id
    if (ofs + 1 >= rec_len) return ofs + 1;
    ofs += 2 + (rec[ofs] << 8 | rec[ofs + 1]);  // skip cipher_suites
    if (ofs >= rec_len) return ofs;
    ofs += 1 + rec[ofs];    // skip compression_methods
    return ofs;
}

static char *a2s_buf(struct ipaddr *a, char *buf)
{
    const char *fmt = ipaddr_family(a) == AF_INET6 ? "[%s]:%d" : "%s:%d";
    snprintf(buf, 64, fmt, ipaddr_str(a, (char [IPADDR_MAXSTRLEN]){}), ipaddr_port(a));
    return buf;
}
#define a2s(a)  a2s_buf(a, (char [64]){})

static int open_socket(int family, bool transparent);

static int fd_connect(int s, struct ipaddr *addr)
{
    if (!connect(s, ipaddr_sockaddr(addr), ipaddr_len(addr)))
        return 0;   // succeeded immediately?
    if (errno != EINPROGRESS)
        return -1;
    if (fdout(s, -1))
        return -1;
    int err;
    socklen_t errlen = sizeof(err);
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &errlen))
        return -1;
    if (err) {
        errno = err;
        return -1;
    }
    return 0;
}

// custom version of tcp_connect() that optionally binds to source address
static int my_tcp_connect(struct ipaddr *src, struct ipaddr *dst)
{
    int s = open_socket(ipaddr_family(dst), tproxy & TPROXY_OUT);
    if (s < 0)
        return -1;
    if (tproxy & TPROXY_OUT) {
        if (bind(s, ipaddr_sockaddr(src), ipaddr_len(src))) {
            perror("bind");
            goto fail;
        }
    }
    if (fd_connect(s, dst)) {
        perror("connect");
        goto fail;
    }
    int h = tcp_fromfd(s);
    if (h < 0) {
        perror("tcp_fromfd");
        goto fail;
    }
    return h;
fail:
    fdclean(s); // clear libdill state
    close(s);
    return -1;
}

coroutine void do_proxy(int fd)
{
    struct ipaddr src;
    socklen_t addrlen = sizeof(src);
    if (getpeername(fd, (struct sockaddr *)&src, &addrlen)) {
        perror("getpeername");
        close(fd);
        return;
    }

    struct ipaddr dst;
    addrlen = sizeof(dst);
    if (tproxy & TPROXY_IN) {
        // for TPROXY, getsockname() returns destination address
        if (getsockname(fd, (struct sockaddr *)&dst, &addrlen)) {
            perror("getsockname");
            close(fd);
            return;
        }
    } else {
        // assume REDIRECT target
        if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &dst, &addrlen) &&
            getsockopt(fd, SOL_IPV6, SO_ORIGINAL_DST, &dst, &addrlen)) {
            perror("getsockopt(SO_ORIGINAL_DST)");
            close(fd);
            return;
        }
    }
    if (ipaddr_equal(&dst, &listen_ip4, 0) ||
        ipaddr_equal(&dst, &listen_ip6, 0)) {
        pr_info("Refusing to talk to self\n");
        close(fd);
        return;
    }

    int s = tcp_fromfd(fd);
    if (s < 0) {
        perror("tcp_fromfd");
        close(fd);
        return;
    }

    int s_rem = my_tcp_connect(&src, &dst);
    if (s_rem < 0) {
        tcp_close(s, -1);
        return;
    }

    pr_info("Connect %s <--> %s\n", a2s(&src), a2s(&dst));
    int64_t sent = 0, rcvd = 0;

    uint8_t hdr[5];
    if (brecv(s, hdr, 5, -1)) goto fail0;
    if (hdr[0] != TLS_HANDSHAKE) {
        pr_info("Expected TLS_HANDSHAKE, got %d\n", hdr[0]);
        goto fail0;
    }
    int rec_len = hdr[3] << 8 | hdr[4];
    if (rec_len == 0 || rec_len > 0x4000) {
        pr_info("Bad TLS handshake rec_len = %d\n", rec_len);
        goto fail0;
    }
    pr_debug("TLS handshake rec_len = %d\n", rec_len);

    uint8_t rec[0x4000];
    if (brecv(s, rec, rec_len, -1)) goto fail0;
    if (rec[0] != TLS_CLIENT_HELLO) {
        pr_info("Expected TLS_CLIENT_HELLO, got %d\n", rec[0]);
        goto fail0;
    }

    int ofs = getofs(rec, rec_len);
    pr_debug("TLS hello offset = %d\n", ofs);
    if (ofs >= rec_len) {
        // already split, or no extensions
        if (bsend(s_rem, hdr, 5, -1)) goto fail0;
        if (bsend(s_rem, rec, rec_len, -1)) goto fail0;
    } else {
        hdr[3] = ofs >> 8;
        hdr[4] = ofs & 0xff;
        if (bsend(s_rem, hdr, 5, -1)) goto fail0;
        if (bsend(s_rem, rec, ofs, -1)) goto fail0;

        int len = rec_len - ofs;
        hdr[3] = len >> 8;
        hdr[4] = len & 0xff;
        if (bsend(s_rem, hdr, 5, -1)) goto fail0;
        if (bsend(s_rem, rec + ofs, len, -1)) goto fail0;
    }

    int och[2], ich[2];
    if (chmake(och)) goto fail0;
    if (chmake(ich)) goto fail1;

    int ob = go(forward(s, s_rem, och[1]));
    if (ob < 0) goto fail2;
    int ib = go(forward(s_rem, s, ich[1]));
    if (ib < 0) goto fail3;

    struct chclause cc[] = {
        { CHRECV, och[0], &sent, sizeof(sent) },
        { CHRECV, ich[0], &rcvd, sizeof(rcvd) },
    };

    // wait until either side closes connection or error occurs
    switch (choose(cc, 2, -1)) {
    case 0: // incoming connection closed
        tcp_done(s_rem, -1);
        chrecv(ich[0], &rcvd, sizeof(rcvd), -1);
        break;
    case 1: // outgoing connection closed
        tcp_done(s, -1);
        chrecv(och[0], &sent, sizeof(sent), -1);
        break;
    }

    pr_info("Disconnect %s <--> %s (%"PRId64" bytes sent, "
            "%"PRId64" bytes rcvd)\n", a2s(&src), a2s(&dst), sent, rcvd);
    hclose(ib);
fail3:
    hclose(ob);
fail2:
    hclose(ich[0]);
    hclose(ich[1]);
fail1:
    hclose(och[0]);
    hclose(och[1]);
fail0:
    tcp_close(s_rem, -1);
    tcp_close(s, -1);
}

coroutine void do_accept(int s)
{
    while (1) {
        if (fdin(s, -1)) {
            perror("fdin");
            return;
        }
        struct ipaddr addr;
        socklen_t addrlen = sizeof(addr);
        int fd = accept(s, (struct sockaddr *)&addr, &addrlen);
        if (fd < 0) {
            perror("accept");
            continue;
        }
        if (bundle_go(workers, do_proxy(fd))) {
            perror("bundle_go");
            close(fd);
            return;
        }
    }
}

static int open_socket(int family, bool transparent)
{
    int s = socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (s < 0) {
        perror("socket");
        return -1;
    }
    const int yes = 1;
    if (family == AF_INET6) {
        if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes))) {
            perror("setsockopt(IPV6_V6ONLY)");
            goto fail;
        }
        if (transparent) {
            if (setsockopt(s, IPPROTO_IPV6, IPV6_TRANSPARENT, &yes, sizeof(yes))) {
                perror("setsockopt(IPV6_TRANSPARENT)");
                goto fail;
            }
        }
    } else {
        if (transparent) {
            if (setsockopt(s, IPPROTO_IP, IP_TRANSPARENT, &yes, sizeof(yes))) {
                perror("setsockopt(IP_TRANSPARENT)");
                goto fail;
            }
        }
    }
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes))) {
        perror("setsockopt(SO_REUSEADDR)");
        goto fail;
    }
    return s;
fail:
    close(s);
    return -1;
}

static int setup_socket(const char *iface, int port, int mode)
{
    struct ipaddr *addr = mode == IPADDR_IPV4 ? &listen_ip4 : &listen_ip6;
    if (ipaddr_local(addr, iface, port, mode)) {
        perror("ipaddr_local");
        return -1;
    }
    int s = open_socket(ipaddr_family(addr), tproxy & TPROXY_IN);
    if (s < 0)
        return -1;
    if (bind(s, ipaddr_sockaddr(addr), ipaddr_len(addr))) {
        perror("bind");
        goto fail;
    }
    if (listen(s, 10)) {
        perror("listen");
        goto fail;
    }
    pr_info("Listening at %s\n", a2s(addr));
    if (bundle_go(workers, do_accept(s))) {
        perror("bundle_go");
        goto fail;
    }
    return 0;
fail:
    close(s);
    return -1;
}

int main(int argc, char **argv)
{
    char *iface = NULL;
    int port = 5555;
    int mode = 0;
    int opt;
    while ((opt = getopt(argc, argv, "i:p:46tTvh")) != -1) {
        switch (opt) {
        case 'i': iface = optarg; break;
        case 'p': port = atoi(optarg); break;
        case '4': mode = IPADDR_IPV4; break;
        case '6': mode = IPADDR_IPV6; break;
        case 't': tproxy |= TPROXY_IN; break;
        case 'T': tproxy |= TPROXY_OUT; break;
        case 'v': verbose++; break;
        case 'h':
        default:
            pr_error("Usage: %s [-i iface] [-p port] [-46tTvh]\n", argv[0]);
            return 1;
        }
    }
    workers = bundle();
    if (workers < 0) {
        perror("bundle");
        return 1;
    }
    if (mode == 0) {
        if (setup_socket(iface, port, IPADDR_IPV4)) return 1;
        setup_socket(iface, port, IPADDR_IPV6);
    } else {
        if (setup_socket(iface, port, mode)) return 1;
    }
    bundle_wait(workers, -1);
    return 1;
}
