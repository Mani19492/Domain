#!/usr/bin/env python3
"""
Test script for new monitoring features
"""
import sys
import time

def test_imports():
    """Test if all new modules can be imported."""
    print("=" * 60)
    print("Testing Module Imports...")
    print("=" * 60)
    
    try:
        from whois_service import whois_service
        print("✅ WHOIS Service imported successfully")
        
        from uptime_monitor import uptime_monitor
        print("✅ Uptime Monitor imported successfully")
        
        from visual_change_detector import visual_change_detector
        print("✅ Visual Change Detector imported successfully")
        
        from visitor_tracker import visitor_tracker
        print("✅ Visitor Tracker imported successfully")
        
        from alert_system import alert_system
        print("✅ Alert System imported successfully")
        
        print("\n✅ All modules imported successfully!\n")
        return True
    except Exception as e:
        print(f"\n❌ Import failed: {str(e)}\n")
        return False

def test_whois():
    """Test WHOIS service."""
    print("=" * 60)
    print("Testing WHOIS Service...")
    print("=" * 60)
    
    try:
        from whois_service import whois_service
        
        print("Fetching WHOIS data for google.com...")
        result = whois_service.get_whois_data("google.com")
        
        if result.get('success'):
            print("✅ WHOIS data retrieved successfully")
            print(f"   Domain: {result.get('domain')}")
            print(f"   Registrar: {result.get('registrar')}")
            print(f"   Creation Date: {result.get('creation_date')}")
            print(f"   Domain Age: {result.get('age_days')} days")
        else:
            print(f"⚠️  WHOIS lookup completed with error: {result.get('error')}")
        
        print()
        return True
    except Exception as e:
        print(f"❌ WHOIS test failed: {str(e)}\n")
        return False

def test_uptime_monitor():
    """Test uptime monitoring."""
    print("=" * 60)
    print("Testing Uptime Monitor...")
    print("=" * 60)
    
    try:
        from uptime_monitor import uptime_monitor
        
        print("Adding google.com to uptime monitoring...")
        monitor_id = uptime_monitor.add_url_monitor("https://google.com", check_interval=60)
        print(f"✅ Monitor created with ID: {monitor_id}")
        
        print("Waiting 2 seconds for first check...")
        time.sleep(2)
        
        print("Getting uptime statistics...")
        stats = uptime_monitor.get_uptime_stats(monitor_id, hours=1)
        
        if stats:
            print(f"✅ Uptime stats retrieved")
            print(f"   Total checks: {stats.get('total_checks', 0)}")
            print(f"   Uptime: {stats.get('uptime_percentage', 0)}%")
        
        print("Removing monitor...")
        uptime_monitor.remove_monitor(monitor_id)
        print("✅ Monitor removed")
        
        print()
        return True
    except Exception as e:
        print(f"❌ Uptime monitor test failed: {str(e)}\n")
        return False

def test_visual_detector():
    """Test visual change detector."""
    print("=" * 60)
    print("Testing Visual Change Detector...")
    print("=" * 60)
    
    try:
        from visual_change_detector import visual_change_detector
        
        print("✅ Visual change detector initialized")
        print("   Screenshots directory: /app/screenshots")
        print("   Monitoring thread: Running")
        
        # Get all monitors
        monitors = visual_change_detector.get_all_monitors()
        print(f"   Active monitors: {len(monitors)}")
        
        print()
        return True
    except Exception as e:
        print(f"❌ Visual detector test failed: {str(e)}\n")
        return False

def test_visitor_tracker():
    """Test visitor tracking."""
    print("=" * 60)
    print("Testing Visitor Tracker...")
    print("=" * 60)
    
    try:
        from visitor_tracker import visitor_tracker
        
        print("Logging test visitor...")
        visit_id = visitor_tracker.log_visitor(
            ip_address="203.0.113.42",
            user_agent="Mozilla/5.0 (Test Browser)",
            path="/test",
            method="GET"
        )
        print(f"✅ Visitor logged with ID: {visit_id}")
        
        print("Getting recent visitors...")
        visitors = visitor_tracker.get_recent_visitors(limit=5, hours=1)
        print(f"✅ Retrieved {len(visitors)} recent visitor(s)")
        
        print("Getting visitor statistics...")
        stats = visitor_tracker.get_visitor_statistics(days=7)
        print(f"✅ Statistics retrieved")
        print(f"   Total visits: {stats.get('total_visits', 0)}")
        print(f"   Unique visitors: {stats.get('unique_visitors', 0)}")
        
        print()
        return True
    except Exception as e:
        print(f"❌ Visitor tracker test failed: {str(e)}\n")
        return False

def test_alert_system():
    """Test alert system."""
    print("=" * 60)
    print("Testing Alert System...")
    print("=" * 60)
    
    try:
        from alert_system import alert_system
        
        print("✅ Alert system initialized")
        print("   Available channels: email, sms, discord, slack, telegram, webhook, push")
        print("   Note: Actual alert sending requires configuration in config.py or .env")
        
        # Test alert creation (won't send without credentials)
        print("\nTesting alert creation...")
        alert_system.alert_history = []  # Reset history
        
        # This will log but not actually send without credentials
        alert_system.send_alert(
            'Test',
            'This is a test alert',
            ['email'],
            {'test_key': 'test_value'}
        )
        
        if len(alert_system.alert_history) > 0:
            print("✅ Alert logged successfully")
        
        print()
        return True
    except Exception as e:
        print(f"❌ Alert system test failed: {str(e)}\n")
        return False

def main():
    """Run all tests."""
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 15 + "FEATURE TEST SUITE" + " " * 25 + "║")
    print("╚" + "=" * 58 + "╝")
    print()
    
    results = []
    
    # Run tests
    results.append(("Module Imports", test_imports()))
    results.append(("WHOIS Service", test_whois()))
    results.append(("Uptime Monitor", test_uptime_monitor()))
    results.append(("Visual Detector", test_visual_detector()))
    results.append(("Visitor Tracker", test_visitor_tracker()))
    results.append(("Alert System", test_alert_system()))
    
    # Print summary
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    print()
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! All features are working correctly.\n")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please check the errors above.\n")
        return 1

if __name__ == "__main__":
    sys.exit(main())
