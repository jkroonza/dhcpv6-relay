= DHCPv6 Relay

This project is still in infancy.

It was borne from our need to have a DHCPv6 relay agent running dynamically on
our ppp interfaces, ideally we'd have preferred to just run a DHCPv6 server
directly on the hosts but as it turns out the DHCPv6 servers we could obtain
didn't function correctly.

We figured we'd just install a relay agent, turns out in spite of various
references we could not locate one except for dibbler, which as it turns out is
deprecated, similar for wide-dhcpv6.  And so here we try to deal with it.

Must be noted:  The intent here is to eventually:

1.  Dynamically add/remove interfaces for which we relay (either by way of
    events + regex matching, or reloading configuration file listing
    interfaces).
2.  Relay DHCPv6 messages to a unicast server (such as kea).
3.  Install/add routing as and when needed.  Either directly using netlink
    sockets, or by executing external script (the latter has the advantage that
    if the script is configurable this can for example hook into frr).
4.  Possibly provide a filter mechanism on RX from client, and prior to TX to
    client, allowing modifications in both cases.  This is a MAYBE as we don't
    currently see that we will need this.
