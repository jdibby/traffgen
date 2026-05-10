#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
generator.py — Traffic Generator v3.4.0
========================================
Simulates realistic network traffic across a wide range of protocols and
behaviours: DNS, HTTP/HTTPS/HTTP3, FTP, SSH, NTP, BGP, ICMP, SNMP,
DoH, DoT, C2 beacon, DNS exfiltration, LLM/AI DLP simulation (fake PII
uploads to known LLM API endpoints), Metasploit checks, web crawling,
malware/phishing domain probing, ad-tracker HEAD requests, speed-tests,
and more.

Designed to run inside a Docker container as a continuous traffic source
for testing firewalls, IDS/IPS rules, and security analytics pipelines.

Usage (stand-alone):
    python3 generator.py --suite=all --size=M --loop

Usage (Docker default):
    # See CMD in Dockerfile — runs suite=all, size=S, loop
"""