import os
import yaml
import logging
import paramiko
import concurrent.futures
from threading import Lock
TOPOLOGY_FILE = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/network_topology.yaml'
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)
def load_topology():
    with open(TOPOLOGY_FILE) as f:
        data = yaml.safe_load(f)
        if not data or 'topology' not in data:
            logger.error('network_topology.yaml is empty or missing "topology" key.')
            raise ValueError('network_topology.yaml is empty or missing "topology" key.')
        return data['topology']
def ping_device(ip):
    response = os.system(f'ping -c 2 -W 2 {ip.split("/")[0]} > /dev/null 2>&1')
    return response == 0
def ssh_check(ip, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip.split("/")[0], username=username, password=password, timeout=5)
        client.close()
        return True
    except Exception as e:
        logger.warning(f'SSH failed for {ip}: {e}')
        return False
def test_device_connectivity(device, creds, print_lock):
    """Test connectivity for a single device"""
    name = device['name']
    ip = device['mgmt_ip']
    username = creds[name]['username']
    password = creds[name]['password']
    
    ping_ok = ping_device(ip)
    ssh_ok = ssh_check(ip, username, password)
    
    with print_lock:
        logger.info(f'{name}: Ping={ping_ok}, SSH={ssh_ok}')
        print(f'{name}: Ping={ping_ok}, SSH={ssh_ok}')
    
    return name, ping_ok, ssh_ok

def main():
    topology = load_topology()
    devices = topology['devices']
    creds = {
        'SPINE1': {'username': 'admin', 'password': 'cisco123'},
        'SPINE2': {'username': 'admin', 'password': 'Cisco123'},
        'LEAF1': {'username': 'admin', 'password': 'cisco123'},
        'LEAF2': {'username': 'admin', 'password': 'cisco123'},
        'LEAF3': {'username': 'admin', 'password': 'cisco123'},
        'LEAF4': {'username': 'admin', 'password': 'cisco123'},
    }
    
    print_lock = Lock()
    results = []
    
    # Use ThreadPoolExecutor for concurrent connectivity testing
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        future_to_device = {
            executor.submit(test_device_connectivity, device, creds, print_lock): device 
            for device in devices
        }
        
        for future in concurrent.futures.as_completed(future_to_device):
            try:
                name, ping_ok, ssh_ok = future.result()
                results.append((name, ping_ok, ssh_ok))
            except Exception as e:
                device = future_to_device[future]
                logger.error(f"Connectivity test failed for {device['name']}: {e}")
                results.append((device['name'], False, False))
    
    # Return True if all devices are reachable
    return all(ping_ok and ssh_ok for _, ping_ok, ssh_ok in results)
if __name__ == '__main__':
    main()
