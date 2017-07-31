#!/bin/bash

iptables -F
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
