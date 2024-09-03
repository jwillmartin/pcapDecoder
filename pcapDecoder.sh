#!/bin/bash
directory=$(cd ../ &&pwd)

extract() {
    ls *.pcap
    read -rep "Type pcap file from list: " fileName
    
    tshark -r $fileName --disable-protocol wsmp -Tfields -Eseparator=, -e data.data > pcap.txt
}

decode() {
    python3 decodeJ2735.py $fileName
}

processing() {
    extract
    decode
}

processing
