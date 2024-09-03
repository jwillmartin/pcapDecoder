# PCAP Decoder for SAE J2735 Messages

This script decodes PCAP files containing SAE J2735 messages. The decoded output is displayed in the terminal and saved to a file with the same name as the original PCAP file.

**Note:** The script currently outputs data in a dictionary format. Support for JSON and XML formats will be added soon.

## Supported Platforms
- **Linux** (Primary)
- **Windows and macOS** (Adaptation possible)

## Prerequisites

- Python 3
- Tshark

To install the necessary dependencies, run:
```
sudo ./install_dependencies.sh
```

## Usage

1. Execute the script:
```
./pcapDecoder.sh
```
2. Follow the on-screen prompts.

### Version
Version 1.1 – September 3, 2024
