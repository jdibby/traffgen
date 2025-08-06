#!/bin/bash

pgrep -f generator.py > /dev/null

if [ $? -ne 0 ]; then
  echo "PYTHON SCRIPT IS NOT RUNNING"
  exit 1
else
  echo "PYTHON SCRIPT IS RUNNING"
  exit 0
fi
