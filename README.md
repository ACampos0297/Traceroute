# Traceroute
Fast version of tracreout that sends n probes with different TTLs to a given destination. 

Starts 30 threads with TTLs increasing from 1,2,....,n the outputs the results from each probe in order and displays the hop number, DNS name of the router, IP address of the router, the RTT and how many probes were sent for a given TTL. 

Command line arguments:
- Destination (hostname or IP)

Usage: `trace www.google.com`
