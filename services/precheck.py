import os
import yaml
import logging
from datetime import datetime
from netmiko import ConnectHandler
import concurrent.futures
from threading import Lock

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
TOPOLOGY_FILE = os.path.join(BASE_DIR, 'network_topology.yaml')
PRECHECK_DIR = os.path.join(BASE_DIR, 'logs', 'precheck')
os.makedirs(PRECHECK_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

def load_topology():
    with open(TOPOLOGY_FILE) as f:
        return yaml.safe_load(f)['topology']

def save_precheck(device, state):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    fname = f"{device['name']}_{timestamp}.txt"
    path = os.path.join(PRECHECK_DIR, fname)
    with open(path, 'w') as f:
        for cmd, output in state.items():
            f.write(f"===== {cmd} =====\n{output}\n\n")
    logger.info(f"Precheck saved for {device['name']} at {path}")

def collect_device_precheck(device, creds):
    """Collect precheck data from a single device"""
    ip = device['mgmt_ip'].split('/')[0]
    name = device['name']
    username = creds[name]['username']
    password = creds[name]['password']
    
    params = {
        'device_type': 'cisco_ios',
        'host': ip,
        'username': username,
        'password': password,
        'fast_cli': False,
        'timeout': 30,
    }
    
    try:
        logger.info(f"Starting precheck for {name} ({ip})")
        with ConnectHandler(**params) as net_connect:
            net_connect.enable()
            state = {
                'show version': net_connect.send_command('show version'),
                'show running-config': net_connect.send_command('show running-config'),
                'show ip interface brief': net_connect.send_command('show ip interface brief'),
                'show ip route': net_connect.send_command('show ip route'),
                'show ip ospf neighbor': net_connect.send_command('show ip ospf neighbor'),
                'show bgp summary': net_connect.send_command('show bgp summary'),
                'show bfd neighbors': net_connect.send_command('show bfd neighbors'),
                'show nve peers': net_connect.send_command('show nve peers'),
                'show vlan brief': net_connect.send_command('show vlan brief'),
                'show interfaces status': net_connect.send_command('show interfaces status'),
            }
            save_precheck(device, state)
            logger.info(f"✅ Precheck completed for {name}")
            print(f"✅ Precheck completed for {name}")
            return True
    except Exception as e:
        logger.error(f"❌ Precheck failed for {name}: {e}")
        print(f"❌ Precheck failed for {name}: {e}")
        return False

def main():
    """Main function with concurrent precheck processing"""
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
    
    print(f"🚀 Starting concurrent precheck on {len(devices)} devices...")
    print(f"📁 Saving to: {PRECHECK_DIR}")
    print("-" * 60)
    
    # Use ThreadPoolExecutor for concurrent operations
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        future_to_device = {
            executor.submit(collect_device_precheck, device, creds): device 
            for device in devices
        }
        
        for future in concurrent.futures.as_completed(future_to_device):
            device = future_to_device[future]
            try:
                success = future.result()
                results.append((device['name'], success))
            except Exception as e:
                logger.error(f"Precheck failed for {device['name']}: {e}")
                results.append((device['name'], False))
    
    # Calculate results
    successful = sum(1 for _, success in results if success)
    failed = len(results) - successful
    
    print("-" * 60)
    print(f"🎉 Precheck completed!")
    print(f"✅ Successful: {successful}")
    print(f"❌ Failed: {failed}")
    print(f"📁 Logs saved in: {PRECHECK_DIR}")
    
    return failed == 0

if __name__ == '__main__':
    main()
