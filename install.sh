#!/bin/bash

echo "updating python"
apt-get install python &
wait


echo "installing prerequesites"
apt-get install python-scapy -y --force-yes &
wait

apt-get install python-netaddr -y  --force-yes &
wait

apt-get install p0f -y --force-yes &
wait

