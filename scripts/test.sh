#!/usr/bin/env sh
unzip wireshark/wireshark.zip -d wireshark
python -m pytest test/test*.py
rm wireshark/wireshark.zip
