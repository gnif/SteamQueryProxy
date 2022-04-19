# SteamQueryProxy

Valve Steam Query reverse proxy using NFQUEUE to intercept and cache the Steam
Query protocol for misbehaving dedicated servers.

https://developer.valvesoftware.com/wiki/Server_queries

# Rationale

Some dedicated servers under linux have in-built flood protection on for the
Steam Query Port protocol that can not be adjusted or disabled. This causes
issues with websites and services that monitor the server and collect metrics,
causing the server to appear "offline" when this protection is triggered.

This application makes use of netfilter NFQUEUE to intercept the Steam Query
protocol datagrams and reply to them directly from a local cache of values
collected from the game server every 10 seconds.

This issue has been incorrectly identified at times as being caused by provider
DDoS protection, most notibly OVH.

# Risks

There is a chance that the server information could be up to 10 seconds old
which might be flagged by the steam master server as spoofed. Use this at your
own risk.

# Method of operation

At startup and every 10 seconds there after the application attempts to connect
to the game server directly and collect the `A2S_INFO`, `A2S_PLAYER`, and
`A2S_RULES` details which it then caches into ram.

Incoming packets from clients are collected by the application via the NFQUEUE C
interface, which is then parsed for Steam Query protocol packets, anything that
does not match is passed through to the backend application without modification.

When a steam query message is identified to be handled the application manually
crafts a valid reply packet with the appropriate information and sends this to
the client. The intercepted packet is dropped preventing it from reaching the
application.

# Limitations

At current this project does not work with split packet messages, as such
datagrams that exceed 1400 bytes will likely cause issues on servers with long
descriptions or large player counts until this is addressed. This is not a
technical limitation, it just simply has not yet been implemented yet.

# Building

## Dependencies

* cmake
* gcc
* libnetfilter-queue-dev
* libmnl-dev

## Compiling

```
mkdir build
cd build
cmake ../
make
```

# Usage

Add a iptables nfqueue target that processes every incoming packet for the query
port (usually 27015), I recommend using the following rule which will fail safe
even if this application is not running:

    iptables -A INPUT -p udp -m udp --dport 27015 -m length --length 33:57 -j NFQUEUE --queue-num 0 --queue-bypass

After this has been done simply start SteamQueryProxy for the correct queue on
the game port, for example:

    ./SteamQueryProxy 0 27105

You should start to see messages such as the following...

    Got S2C_CHALLENGE:: 0x1545279c
    Got A2S_INFO_REPLY: 203 bytes
    Got A2S_PLAYER_REPLY: 40 bytes
    Got A2S_RULES_REPLY: 1258 bytes
    A2S_INFO 0x4c1eeb6b
    A2S_INFO 0x86be12d4
    A2S_PLAYER 0x4c1eeb6b
    A2S_INFO 0x1a6bb070
    A2S_RULES 0x4c1eeb6b
    A2S_INFO 0x80b77a95
    A2S_INFO 0xb3a8b7ce
    A2S_INFO 0x8f892200
    A2S_INFO 0x064e69ae
    A2S_INFO 0x9eec7936
    A2S_INFO 0x5f934826
    A2S_INFO 0x8888ab3a
    A2S_PLAYER 0x5f934826
    A2S_RULES 0x5f934826
    A2S_INFO 0xc68183a1
    A2S_INFO 0xd3e0952d
    A2S_INFO 0xafcf3596
    A2S_INFO 0xff49c049

Messages starting with `Got` are sucessful requests for the actual server
information from the game server which are cached in ram. All other messages are
intercepted messages which have been handled by this application and the
security challenge that has been used for the request.

# Donations

If you like this project and find it useful and would like to help out you can
support this project directly by using the following platforms.

* [GitHub](https://github.com/sponsors/gnif)
* [Ko-Fi](https://ko-fi.com/lookingglass)
* [Patreon](https://www.patreon.com/gnif)
* [Paypal](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=ESQ72XUPGKXRY)
* BTC - 14ZFcYjsKPiVreHqcaekvHGL846u3ZuT13
* ETH - 0x6f8aEe454384122bF9ed28f025FBCe2Bce98db85

# License

MIT License

Copyright (c) 2022 Geoffrey McRae

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
