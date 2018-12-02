#!/bin/bash
sudo tcpdump -G 150 -W 1 -i s2-eth1 -nn -s0 -v -w wireshark/s2-eth1-h1-ping-h5.pcap &
sudo tcpdump -G 150 -W 1 -i s2-eth1 -nn -s0 -v -w wireshark/s2-eth1-h2-ping-h5.pcap &
sudo tcpdump -G 150 -W 1 -i s3-eth1 -nn -s0 -v -w wireshark/s3-eth1-h1-ping-h5.pcap &
sudo tcpdump -G 150 -W 1 -i s3-eth1 -nn -s0 -v -w wireshark/s3-eth1-h2-ping-h5.pcap &
sudo tcpdump -G 150 -W 1 -i s2-eth1 -nn -s0 -v -w wireshark/s2-eth1-iperf-h1-h4 &
sudo tcpdump -G 150 -W 1 -i s3-eth1 -nn -s0 -v -w wireshark/s3-eth1-iperf-h1-h4 &
sudo tcpdump -G 150 -W 1 -i s5-eth1 -nn -s0 -v -w wireshark/s5-eth1-iperf-udp-h1-h5 &