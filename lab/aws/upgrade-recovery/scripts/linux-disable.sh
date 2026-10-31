#!/bin/bash
systemctl disable --now bower
systemctl is-active bower || true
