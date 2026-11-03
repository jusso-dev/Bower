#!/bin/bash
echo "{\"boot\":\"$(cat /proc/sys/kernel/random/boot_id)\"}"
