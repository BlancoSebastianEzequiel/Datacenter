import os
import utils


def test_ping_h1_h5_and_h2_h5_balance_of_charges():
    utils.get_output(
        "wireshark/s2-eth1-h1-ping-h5.pcap", "test/s2-ping-h1-h5.txt")
    utils.get_output(
        "wireshark/s2-eth1-h2-ping-h5.pcap", "test/s2-ping-h2-h5.txt")
    utils.get_output(
        "wireshark/s3-eth1-h1-ping-h5.pcap", "test/s3-ping-h1-h5.txt")
    utils.get_output(
        "wireshark/s3-eth1-h2-ping-h5.pcap", "test/s3-ping-h2-h5.txt")

    def callback(x):
        return x['dst'] == '10.0.0.5' and x['protocol'] == 'ICMP'

    df_1 = utils.get_df("test/s2-ping-h1-h5.txt")
    df_1.columns = ['src', 'dst', 'protocol']
    df_1 = utils.filter_by(df_1, ['dst', 'protocol'], callback)
    size_1 = len(df_1.index)

    df_2 = utils.get_df("test/s2-ping-h2-h5.txt")
    df_2.columns = ['src', 'dst', 'protocol']
    df_2 = utils.filter_by(df_2, ['dst', 'protocol'], callback)
    size_2 = len(df_2.index)

    df_3 = utils.get_df("test/s3-ping-h1-h5.txt")
    df_3.columns = ['src', 'dst', 'protocol']
    df_3 = utils.filter_by(df_3, ['dst', 'protocol'], callback)
    size_3 = len(df_3.index)

    df_4 = utils.get_df("test/s3-ping-h2-h5.txt")
    df_4.columns = ['src', 'dst', 'protocol']
    df_4 = utils.filter_by(df_4, ['dst', 'protocol'], callback)
    size_4 = len(df_4.index)

    os.system("rm test/s2-ping-h1-h5.txt")
    os.system("rm test/s2-ping-h2-h5.txt")
    os.system("rm test/s3-ping-h1-h5.txt")
    os.system("rm test/s3-ping-h2-h5.txt")

    ecmp_h1_h5 = (size_1 == 0 and size_3 != 0) or (size_1 != 0 and size_3 == 0)
    ecmp_h2_h5 = (size_2 == 0 and size_4 != 0) or (size_2 != 0 and size_4 == 0)
    assert ecmp_h1_h5 and ecmp_h2_h5
