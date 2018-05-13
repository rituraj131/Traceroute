# Traceroute
Purpose: 
Implement a fast version of traceroute and learn about the topology of the Internet. 

Description:
Traceroute operates by sending a sequence of probes towards a given destination D. Each probe i
has the TTL value set to i, which causes router i along the path to discard the packet and generate
a “TTL expired” message. By iterating through TTL values 1, 2, …, N, where N is the number of
hops in the path, traceroute obtains the IP addresses of each router. Performing reverse DNS
lookups on these addresses, traceroute also prints the corresponding DNS names. In this
homework, your traceroute should be optimized to send all probes at once (i.e., in parallel)
instead of sequentially. This allows it to complete much faster than the regular version. 

How to use:
run master branch main.cpp with a host to be tracerouted.
