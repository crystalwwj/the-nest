---
sidebar_position: 3
---

# Memory Allocation

I was reading through some binary exploit writeups from the GitHub Security Team, mainly [Getting root on Ubuntu through wishful thinking](https://securitylab.github.com/research/ubuntu-accountsservice-CVE-2021-3939/), and got really interested in how memory was managed across threads and processes. 

I wanted answers on:
* memory structure and allocation during multi-threading, multi-processing, and parent/child processes
* how to transfer memory, e.g. malloc-ed chunks, across threads/processes
* other characteristics or tips when exploiting in such situations
