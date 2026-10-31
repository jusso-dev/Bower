#!/bin/bash
systemctl stop bower-sender-{{STREAM}} || true
sleep 1
cat /var/lib/bower-sender/{{STREAM}}.json
