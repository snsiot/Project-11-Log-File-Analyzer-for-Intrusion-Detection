import re
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

def load_blacklist(path='blacklist.txt'):
    try:
        with open(path) as f:
            return set(ip.strip() for ip in f)
    except FileNotFoundError:
        return set()

def parse_ssh_log(file_path):
    ssh_data = []
    pattern = r'(?P<date>\w+ \d+ \d+:\d+:\d+).*sshd.*Failed password.*from (?P<ip>\d+\.\d+\.\d+\.\d+)'

    with open(file_path, 'r') as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                ssh_data.append({
                    'type': 'SSH',
                    'ip': match.group('ip'),
                    'timestamp': match.group('date')
                })

    return pd.DataFrame(ssh_data)

def detect_brute_force(df):
    counts = df['ip'].value_counts()
    return counts[counts > 5]

def visualize(df):
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df = df.dropna(subset=['timestamp'])

    plt.figure(figsize=(10,5))
    df['timestamp'].dt.hour.value_counts().sort_index().plot(kind='bar')
    plt.title('Log Activity by Hour')
    plt.xlabel('Hour')
    plt.ylabel('Count')
    plt.savefig('visuals/activity_plot.png')
    plt.close()

def save_report(threats, filename="incident_report.csv"):
    threats.to_csv(filename)
    print(f"[+] Incident report saved to {filename}")

def main():
    blacklist = load_blacklist()
    df = parse_ssh_log('logs/sample_ssh.log')
    
    df['blacklisted'] = df['ip'].isin(blacklist)
    
    brute_ips = detect_brute_force(df)
    report = df[df['ip'].isin(brute_ips.index)]

    visualize(df)
    save_report(report_
