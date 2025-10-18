#!/usr/bin/env python3
"""
Verification script to check if all fixes are working correctly.
Run this before starting the application to ensure everything is set up correctly.
"""

import sys
import importlib.util

def check_import(module_name):
    """Check if a module can be imported."""
    try:
        spec = importlib.util.find_spec(module_name)
        if spec is None:
            return False, f"Module {module_name} not found"
        return True, f"✅ {module_name}"
    except Exception as e:
        return False, f"❌ {module_name}: {str(e)}"

def check_file_syntax(filename):
    """Check if a Python file has correct syntax."""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            compile(f.read(), filename, 'exec')
        return True, f"✅ {filename}"
    except SyntaxError as e:
        return False, f"❌ {filename}: Syntax error at line {e.lineno}"
    except Exception as e:
        return False, f"❌ {filename}: {str(e)}"

def main():
    print("=" * 60)
    print("Verification Script - Checking All Fixes")
    print("=" * 60)
    print()

    all_passed = True

    # Check critical Python files syntax
    print("1. Checking Python File Syntax...")
    print("-" * 60)
    critical_files = [
        'app.py',
        'real_time_monitor.py',
        'api_integration.py',
        'recon.py',
        'ai_threat_predictor.py'
    ]

    for filename in critical_files:
        try:
            passed, message = check_file_syntax(filename)
            print(message)
            if not passed:
                all_passed = False
        except FileNotFoundError:
            print(f"⚠️  {filename}: File not found")
            all_passed = False

    print()

    # Check critical imports
    print("2. Checking Critical Imports...")
    print("-" * 60)

    # Test the fixed import
    try:
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        print("✅ email.mime imports (MIMEText, MIMEMultipart)")
    except ImportError as e:
        print(f"❌ email.mime imports: {e}")
        all_passed = False

    # Test Flask imports
    critical_modules = [
        'flask',
        'flask_socketio',
        'flask_restful',
        'flask_limiter',
        'flask_cors'
    ]

    for module in critical_modules:
        passed, message = check_import(module)
        print(message)
        if not passed:
            all_passed = False

    print()

    # Check Flask-SocketIO configuration
    print("3. Checking Flask-SocketIO Configuration...")
    print("-" * 60)

    try:
        with open('app.py', 'r', encoding='utf-8') as f:
            content = f.read()
            if "async_mode='threading'" in content:
                print("✅ SocketIO configured with threading mode")
            else:
                print("❌ SocketIO not configured with threading mode")
                all_passed = False
    except Exception as e:
        print(f"❌ Error checking app.py: {e}")
        all_passed = False

    print()

    # Check requirements.txt
    print("4. Checking Dependencies...")
    print("-" * 60)

    try:
        with open('requirements.txt', 'r', encoding='utf-8') as f:
            content = f.read()

            if 'eventlet' in content:
                print("⚠️  Warning: eventlet still in requirements.txt (should be removed)")
                all_passed = False
            else:
                print("✅ eventlet not in requirements (correct)")

            if 'Flask-SocketIO' in content:
                print("✅ Flask-SocketIO in requirements")
            else:
                print("❌ Flask-SocketIO missing from requirements")
                all_passed = False

            if 'simple-websocket' in content or 'python-engineio' in content:
                print("✅ WebSocket dependencies present")
            else:
                print("⚠️  Warning: WebSocket dependencies may be missing")
    except Exception as e:
        print(f"❌ Error checking requirements.txt: {e}")
        all_passed = False

    print()

    # Check environment file
    print("5. Checking Environment Configuration...")
    print("-" * 60)

    try:
        with open('.env', 'r', encoding='utf-8') as f:
            print("✅ .env file exists")
    except FileNotFoundError:
        print("⚠️  Warning: .env file not found (copy from .env.example)")
        print("   The app will work with limited functionality")

    try:
        with open('.env.example', 'r', encoding='utf-8') as f:
            print("✅ .env.example file exists")
    except FileNotFoundError:
        print("⚠️  Warning: .env.example not found")

    print()

    # Final summary
    print("=" * 60)
    if all_passed:
        print("✅ ALL CHECKS PASSED!")
        print()
        print("Your application is ready to run. Execute:")
        print("  python app.py")
        print()
        print("Then open: http://localhost:5000")
    else:
        print("❌ SOME CHECKS FAILED")
        print()
        print("Please review the errors above and:")
        print("1. Make sure all dependencies are installed: pip install -r requirements.txt")
        print("2. Check that all Python files have correct syntax")
        print("3. Verify .env file is configured")
        print()
        print("For detailed help, see:")
        print("  - SETUP_GUIDE.md")
        print("  - FIX_SUMMARY.md")
        print("  - QUICK_START.md")
    print("=" * 60)

    return 0 if all_passed else 1

if __name__ == '__main__':
    sys.exit(main())
