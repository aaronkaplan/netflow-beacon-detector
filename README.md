# Netflow Beacon Detector

A CLI tool to detect beacon traffic in netflow nfcap/nfdump files

The Netflow Beacon Detector is a Python CLI tool designed to analyze netflow files (v5, v7, or v9) and identify periodic beacon traffic based on specified time intervals. This tool helps network administrators and security analysts detect unusual patterns in network traffic.

## Features

- Reads netflow files in v5, v7, or v9 formats.
- Identifies IP addresses (both IPv4 and IPv6) that appear at least once in specified time intervals.
- Supports customizable interval settings for analysis (default is 60 minutes).
- Outputs the source IP addresses and the count of packets for identified beacons.

## Installation

To install the required dependencies, run the following command:

```
pip install -r requirements.txt
```

## Usage

To use the Netflow Beacon Detector, run the following command in your terminal:

```
python src/netflow_beacon_detector.py -f <path_to_netflow_file> -i <interval_in_minutes>
```

### Parameters

- `-f` or `--file`: Path to the netflow file to be analyzed (required).
- `-i` or `--interval`: Time interval in minutes for detecting periodic beacons (optional, defaults to 60).

## Example

```
python src/netflow_beacon_detector.py -f /path/to/netflow/file -i 30
```

This command will analyze the specified netflow file and look for periodic beacon traffic every 30 minutes.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
