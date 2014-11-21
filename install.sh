#!/bin/bash

echo "updating python"
apt-get install python &
wait


echo "installing prerequesites"
apt-get install python-scapy &
wait
apt-get install python-netaddr &
wait
