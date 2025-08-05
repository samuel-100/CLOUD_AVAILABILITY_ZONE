#!/usr/bin/env python3
"""
API Configuration Management for Network Automation

Secure handling of API keys and configuration for AI integration
"""

import os
import json
from pathlib import Path
from typing import Optional, Dict, Any

class APIConfig:
    """Secure API configuration manager"""
    
    def __init__(self):
        self.config_dir = Path(__file__).parent
        self.config_file = self.config_dir / "api_keys.json"
        self.env_file = self.config_dir.parent / ".env"
        
        # Create config directory if it doesn't exist
        self.config_dir.mkdir(exist_ok=True)
        
    def set_anthropic_key(self, api_key: str) -> bool:
        """Set Anthropic API key securely"""
        try:
            # Validate key format (basic check)
            if not api_key.startswith('sk-ant-'):
                print("⚠️  Warning: API key doesn't match expected format (should start with 'sk-ant-')")
                confirm = input("Continue anyway? (y/N): ").strip().lower()
                if confirm != 'y':
                    return False
            
            # Save to environment variable
            os.environ['ANTHROPIC_API_KEY'] = api_key
            
            # Save to .env file for persistence
            env_content = f"ANTHROPIC_API_KEY={api_key}\n"
            
            # Check if .env exists and update or create
            if self.env_file.exists():
                with open(self.env_file, 'r') as f:
                    lines = f.readlines()
                
                # Update existing key or add new one
                updated = False
                for i, line in enumerate(lines):
                    if line.startswith('ANTHROPIC_API_KEY='):
                        lines[i] = env_content
                        updated = True
                        break
                
                if not updated:
                    lines.append(env_content)
                
                with open(self.env_file, 'w') as f:
                    f.writelines(lines)
            else:
                with open(self.env_file, 'w') as f:
                    f.write(env_content)
            
            print("✅ Anthropic API key configured successfully!")
            return True
            
        except Exception as e:
            print(f"❌ Failed to set API key: {e}")
            return False
    
    def get_anthropic_key(self) -> Optional[str]:
        """Get Anthropic API key from environment or config"""
        # Try environment variable first
        key = os.getenv('ANTHROPIC_API_KEY')
        if key:
            return key
        
        # Try .env file
        if self.env_file.exists():
            try:
                with open(self.env_file, 'r') as f:
                    for line in f:
                        if line.startswith('ANTHROPIC_API_KEY='):
                            return line.split('=', 1)[1].strip()
            except Exception:
                pass
        
        return None
    
    def test_anthropic_connection(self) -> bool:
        """Test Anthropic API connection"""
        key = self.get_anthropic_key()
        if not key:
            print("❌ No API key found")
            return False
        
        try:
            import requests
            
            headers = {
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            }
            
            data = {
                "model": "claude-3-sonnet-20240229",
                "max_tokens": 10,
                "messages": [{"role": "user", "content": "Hello"}]
            }
            
            response = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json=data,
                timeout=10
            )
            
            if response.status_code == 200:
                print("✅ Anthropic API connection successful!")
                return True
            else:
                print(f"❌ API connection failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Connection test failed: {e}")
            return False
    
    def load_env_file(self):
        """Load environment variables from .env file"""
        if self.env_file.exists():
            try:
                with open(self.env_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, value = line.split('=', 1)
                            os.environ[key] = value
                print("✅ Environment variables loaded from .env file")
            except Exception as e:
                print(f"⚠️  Failed to load .env file: {e}")

def main():
    """Interactive API key configuration"""
    config = APIConfig()
    
    print("🤖 ANTHROPIC API KEY CONFIGURATION")
    print("=" * 50)
    
    # Check current status
    current_key = config.get_anthropic_key()
    if current_key:
        masked_key = current_key[:10] + "..." + current_key[-4:] if len(current_key) > 14 else "***"
        print(f"Current API key: {masked_key}")
        
        # Test current key
        if config.test_anthropic_connection():
            print("Current key is working!")
            update = input("Update API key anyway? (y/N): ").strip().lower()
            if update != 'y':
                return
        else:
            print("Current key is not working, please update it.")
    else:
        print("No API key configured.")
    
    # Get new API key
    print("\nPlease enter your Anthropic API key:")
    print("(You can find this at: https://console.anthropic.com/)")
    
    api_key = input("API Key: ").strip()
    
    if not api_key:
        print("❌ No API key provided")
        return
    
    # Set the key
    if config.set_anthropic_key(api_key):
        # Test the new key
        print("\n🧪 Testing API connection...")
        config.test_anthropic_connection()
    
    print("\n🚀 You can now use AI features in the network automation system!")

if __name__ == "__main__":
    main()