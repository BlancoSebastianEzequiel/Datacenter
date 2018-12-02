#!/usr/bin/env sh
if [ -f wireshark/wireshark.zip ]; then
    unzip wireshark/wireshark.zip -d wireshark
fi
python -m pytest test/test*.py
if [ -f wireshark/wireshark.zip ]; then
    rm wireshark/wireshark.zip
fi
