#!/bin/bash

sysctl -w net.ipv4.tcp_congestion_control=bbr
sysctl -w net.ipv4.tcp_congestion_control=lotspeed
sysctl -w net.ipv4.tcp_no_metrics_save=1