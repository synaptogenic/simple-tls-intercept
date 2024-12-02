
# Simple TLS Intercept

This program intercepts TLS traffic originating from your computer. It is
useful for snooping on applications you run that talk to services over TLS,
which is most everything these days.

## Problem

When intercepting TLS traffic it is common to use a TLS proxy. However, there
are issues with this approach. Primarily, using a proxy requires that the
application collaborate in its own interception. It will need to respect the
proxy settings you have configured. This is often not implemented in
application code, libraries, or SDKs so applications will just ignore these
settings. Secondarily, the client is entirely aware that their traffic is being
intercepted since they have to format their traffic in a way that the proxy can
handle it, either through HTTP Proxy or SOCKS. If an application doesn't desire
to be proxied, it can just opt out of doing any of this. Additionally, the
server is often aware that the traffic was intercepted by a proxy as most proxy
software will add bits of information that indicates to the server that the
traffic was proxied.

## Proposed Solution

An alternative to a proxy is to perform a [MITM style attack][mitm-attack]
where you intercept the TLS connection to the server and establish your own TLS
connection. You can then relay and view the plain text traffic between the
application and the server. Typically, applications will hard code DNS names
and specific ports to communicate with the server on (or just rely on the
default 443). If we hijack DNS resolution for the domains the application is
resolving and bind to 443 locally we can setup an intercept and pretend we are
the server. Since we don't have the private keys of the server, we will need to
generate our own CA and add it to the trust store the application is using.

## Known Issues

### Pinning Certificates or IPs

If the application pins the certificates or IPs for the server then this method
won't work. Some applications might do this to prevent interception of traffic,
however it is not very common. If this is the situation you find yourself in
you would be better served by using tools that can modify the pinned
certificates and IPs at runtime such as debuggers or other dynamic
instrumentation tooling such as [Frida][frida].

### mTLS

If the application contains a certificate/private key that the server requires
then this method will not work. While in principal the intercept could present
the same certificate and use the same private key to establish a TLS connection
with the server, obtaining this information from the application is outside of
the scope of this solution. Most TLS connections are single auth so
encountering this situation should be rare. If this is the situation you find
yourself in this program should be easily modifiable to accept the applications
cert/key on startup.

## TODO

- create newline mode that visualizes traffic and outputs lines
- write readme usage + cli usage/help

[mitm-attack]: https://en.wikipedia.org/wiki/Man-in-the-middle_attack
[frida]: https://frida.re
