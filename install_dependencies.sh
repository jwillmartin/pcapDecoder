#!/bin/bash

# Find Distro
source /etc/os-release
distro=$(echo $PRETTY_NAME | awk 'FS=" " {print $1;}')

apt-get update 

# Dependencies
dependencies="python3 \
    tshark"

# Install dependencies, packages
apt-get -y install $dependencies
