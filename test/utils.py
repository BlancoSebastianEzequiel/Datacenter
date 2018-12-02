import pandas as pd
import numpy as np
import os

np.warnings.filterwarnings('ignore')


def get_df(file_path):
    return pd.read_csv(file_path, low_memory=False, sep='\t')


def filter_ip(df, ip, ip_src_col, ip_dst_col):
    return df[(df[ip_src_col] == ip) | (df[ip_dst_col] == ip)]


def filter_by(df, values, callback):
    return df[df[values].apply(lambda x: callback(x), axis=1)]


def get_output(input_file_name, output_file_name):
    cmd = "tshark -T fields -E header=y -e ip.src -e ip.dst " \
          "-e _ws.col.Protocol -r " + input_file_name + " > " + output_file_name
    os.system(cmd)


def rtt_field_to_float(x, rtt_col):
    if x[rtt_col] == 'None':
        x[rtt_col] = None
        return x
    x[rtt_col] = float(x[rtt_col])
    return x
