import os
import utils


def test_udp_denial_of_service():
    utils.get_output(
        "wireshark/s5-eth1-iperf-udp-h1-h5.pcap", "test/s5-udp-h1-h5.txt")

    def callback(x):
        return x['dst'] == '10.0.0.5' and x['protocol'] == 'UDP'

    df_1 = utils.get_df("test/s5-udp-h1-h5.txt")
    df_1.columns = ['src', 'dst', 'protocol']
    df_1 = utils.filter_by(df_1, ['dst', 'protocol'], callback)
    size_1 = len(df_1.index)

    assert size_1 < 893

    os.system("rm test/s5-udp-h1-h5.txt")
