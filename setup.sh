#!/usr/bin/env bash

sudo python3 -m ensurepip
sleep 20
sudo python3 -m pip install --target=/mnt/flash/ -r requirements.txt

exit
