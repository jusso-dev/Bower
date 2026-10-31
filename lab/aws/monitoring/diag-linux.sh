#!/bin/bash
systemctl status bower --no-pager -n 0 | head -5
journalctl -u bower --no-pager -n 30 -o cat | cut -c1-400
