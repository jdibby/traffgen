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

Designed for use in controlled lab environments to validate firewalls,
IDS/IPS, SASE, DLP, CASB, and web-filtering policies.

Usage:
    python3 generator.py [--suite SUITE] [--size SIZE] [--loop]

Run  python3 generator.py --help  for full usage.
"""

import argparse
import base64
import binascii
import csv
import errno
import ftplib
import hashlib
import http.client
import imaplib
import importlib.util
import io
import ipaddress
import json
import logging
import math
import os
import platform
import poplib
import queue
import random
import re
import shutil
import signal
import smtplib
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from contextlib import suppress
from pathlib import Path
from typing import Optional

VERSION = "3.4.0"
