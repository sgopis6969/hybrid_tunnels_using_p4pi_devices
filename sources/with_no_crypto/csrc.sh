#!/bin/bash
cp tunnel1.p4 /root/bmv2/examples/tunnel1
ls -l  /root/bmv2/examples/tunnel1/tunnel1.p4
ls -l  tunnel1.p4
systemctl stop bmv2.service
/usr/bin/bmv2-start1
