#!/usr/bin/env python3
"""
Test script to verify the Passive OSINT Platform installation and basic functionality.
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from passive_osint.core.config import Config
    from passive_osint.core.engine import ReconEngine
    from passive_osint.reports.generator import ReportGenerator
    print("[OK] Successfully imported all core modules")
except ImportError as e:
    print(f"[ERROR] Import error: {e}")
    sys.exit(1)

def test_config():
    """Test configuration loading."""
    print("\n--- Testing Configuration ---")
    try:
        config = Config()
        print("[OK] Configuration loaded successfully")
        
        # Test default values
        assert config.get('modules.subdomains.enabled') == True
        print("[OK] Default configuration values present")
        
        return True
    except Exception as e:
        print(f"[ERROR] Configuration test failed: {e}")
        return False

def test_engine():
    """Test reconnaissance engine initialization."""
    print("\n--- Testing Recon Engine ---")
    try:
        engine = ReconEngine()
        print("[OK] Recon engine initialized successfully")
        
        # Test domain validation
        domain = engine.validate_domain("example.com")
        assert domain == "example.com"
        print("[OK] Domain validation working")
        
        return True
    except Exception as e:
        print(f"[ERROR] Engine test failed: {e}")
        return False

def test_report_generator():
    """Test report generator."""
    print("\n--- Testing Report Generator ---")
    try:
        generator = ReportGenerator()
        print("[OK] Report generator initialized successfully")
        
        return True
    except Exception as e:
        print(f"[ERROR] Report generator test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("Passive OSINT Platform - Installation Test")
    print("=" * 50)
    
    tests = [
        test_config,
        test_engine,
        test_report_generator
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("[OK] All tests passed! Installation is working correctly.")
        print("\nNext steps:")
        print("1. Copy config.yaml and add your API keys")
        print("2. Run: python -m passive_osint.cli --domain example.com")
        return 0
    else:
        print("✗ Some tests failed. Please check the installation.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
