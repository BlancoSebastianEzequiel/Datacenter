import os
import utils


def test_tcp_balance_of_charges():
    utils.get_output("wireshark/s2-eth1-iperf-h1-h4.pcap", "test/s2-h1-h4.txt")
    utils.get_output("wireshark/s3-eth1-iperf-h1-h4.pcap", "test/s3-h1-h4.txt")

    def callback(x):
        return x['dst'] == '10.0.0.4' and x['protocol'] == 'TCP'

    df_1 = utils.get_df("test/s2-h1-h4.txt")
    df_1.columns = ['src', 'dst', 'protocol']
    df_1 = utils.filter_by(df_1, ['dst', 'protocol'], callback)
    size_1 = len(df_1.index)

    df_2 = utils.get_df("test/s3-h1-h4.txt")
    df_2.columns = ['src', 'dst', 'protocol']
    df_2 = utils.filter_by(df_2, ['dst', 'protocol'], callback)
    size_2 = len(df_2.index)

    os.system("rm test/s2-h1-h4.txt")
    os.system("rm test/s3-h1-h4.txt")

    assert (size_1 == 0 and size_2 != 0) or (size_1 != 0 and size_2 == 0)
