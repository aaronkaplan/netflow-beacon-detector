import click
from datetime import datetime, timedelta
from collections import defaultdict
from utils import read_netflow_file

@click.command()
@click.argument('netflow_file', type=click.Path(exists=True))
@click.option('-i', '--interval', default=60, help='Interval in minutes to check for periodic beacons (default: 60)')
def detect_beacons(netflow_file, interval):
    """Detect periodic beacon traffic from a netflow file."""
    interval_seconds = interval * 60
    beacon_counts = defaultdict(lambda: defaultdict(int))
    
    # Read netflow records from the file
    records = read_netflow_file(netflow_file)

    # Process each record
    for record in records:
        timestamp = datetime.fromtimestamp(record['timestamp'])
        src_ip = record['src_ip']
        
        # Round down to the nearest interval
        interval_start = timestamp - timedelta(seconds=timestamp.second % interval_seconds,
                                               microseconds=timestamp.microsecond)
        
        beacon_counts[(src_ip, interval_start)] += 1

    # Identify and print beacons
    beacons = defaultdict(int)
    for (src_ip, interval_start), count in beacon_counts.items():
        if count >= 1:  # At least one packet in the interval
            beacons[src_ip] += count

    click.echo("Detected periodic beacons:")
    for ip, count in beacons.items():
        click.echo(f"{ip}: {count} packets")

if __name__ == '__main__':
    detect_beacons()