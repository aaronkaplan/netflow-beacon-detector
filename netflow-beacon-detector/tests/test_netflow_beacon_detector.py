import pytest
from src.netflow_beacon_detector import detect_beacons

def test_detect_beacons_with_valid_data():
    # Mock data representing a netflow file with periodic beacons
    netflow_data = [
        {"src_ip": "192.168.1.1", "timestamp": 1609459200},  # 2021-01-01 00:00:00
        {"src_ip": "192.168.1.1", "timestamp": 1609462800},  # 2021-01-01 01:00:00
        {"src_ip": "192.168.1.2", "timestamp": 1609459200},
        {"src_ip": "192.168.1.2", "timestamp": 1609466400},  # 2021-01-01 02:00:00
        {"src_ip": "192.168.1.1", "timestamp": 1609466400},
    ]
    
    interval = 60  # 1 hour
    expected_output = {
        "192.168.1.1": 3,
        "192.168.1.2": 2,
    }
    
    result = detect_beacons(netflow_data, interval)
    assert result == expected_output

def test_detect_beacons_with_no_data():
    netflow_data = []
    interval = 60
    expected_output = {}
    
    result = detect_beacons(netflow_data, interval)
    assert result == expected_output

def test_detect_beacons_with_non_periodic_data():
    netflow_data = [
        {"src_ip": "192.168.1.1", "timestamp": 1609459200},
        {"src_ip": "192.168.1.1", "timestamp": 1609462800},  # 1 hour apart
        {"src_ip": "192.168.1.1", "timestamp": 1609466400},  # 2 hours apart
    ]
    
    interval = 60  # 1 hour
    expected_output = {
        "192.168.1.1": 1,  # Only counts the first hour
    }
    
    result = detect_beacons(netflow_data, interval)
    assert result == expected_output

def test_detect_beacons_with_mixed_data():
    netflow_data = [
        {"src_ip": "192.168.1.1", "timestamp": 1609459200},
        {"src_ip": "192.168.1.2", "timestamp": 1609459200},
        {"src_ip": "192.168.1.1", "timestamp": 1609462800},
        {"src_ip": "192.168.1.2", "timestamp": 1609466400},
        {"src_ip": "192.168.1.1", "timestamp": 1609466400},
    ]
    
    interval = 60  # 1 hour
    expected_output = {
        "192.168.1.1": 3,
        "192.168.1.2": 2,
    }
    
    result = detect_beacons(netflow_data, interval)
    assert result == expected_output