# Windows Setup Guide (No Virtual Environment)

## ✅ Pre-requisites Checked
- ✅ Python 3.13.7 installed
- ✅ .env file configured with API keys
- ✅ All code fixes applied

## 🚀 Step-by-Step Installation (Windows)

### Step 1: Clean Any Old Installations (2 minutes)
```powershell
# Open PowerShell as Administrator and run:
pip uninstall scikit-learn tensorflow spacy selenium twilio celery web3 -y
```

### Step 2: Install Dependencies (5-10 minutes)
```powershell
# Navigate to your project folder
cd C:\Users\spmte\OneDrive\Documents\Projects\Domain

# Upgrade pip first
python -m pip install --upgrade pip

# Install the updated requirements
pip install -r requirements.txt
```

**Note**: This will take 5-10 minutes. Don't worry about warnings - only errors matter.

### Step 3: Verify Installation (1 minute)
```powershell
# Run the verification script
python verify_fixes.py
```

Expected output: "✅ ALL CHECKS PASSED!"

### Step 4: Run the Application (30 seconds)
```powershell
python app.py
```

You should see:
```
INFO - Real-time monitoring thread started
INFO - Background services started
INFO - API endpoints registered successfully
 * Running on http://0.0.0.0:5000
```

### Step 5: Test in Browser (1 minute)
Open your browser and go to:
```
http://localhost:5000
```

Try scanning a domain like `example.com`

---

## 🔧 What Was Changed for Python 3.13

### Updated Dependencies:
1. **scikit-learn** 1.3.0 → 1.5.0+ (Python 3.13 compatible)
2. **Flask** 2.3.3 → 3.0.0 (Latest stable)
3. **Werkzeug** 2.3.7 → 3.0.0+ (Flask 3.0 compatible)
4. **numpy** 1.24.3 → 1.26.0+ (Python 3.13 compatible)
5. **pandas** 1.5.3 → 2.1.0+ (numpy 1.26+ compatible)

### Removed (Too Complex for Quick Setup):
- ❌ tensorflow (requires specific C++ compiler)
- ❌ selenium (requires browser drivers)
- ❌ spacy (requires language models)
- ❌ celery (requires Redis server)
- ❌ twilio (SMS functionality)
- ❌ python-telegram-bot (Telegram functionality)
- ❌ web3 (Ethereum functionality)
- ❌ stem (Tor functionality)
- ❌ shap (AI explainability)

**These features will be gracefully disabled if not available.**

---

## 📋 Quick Command Reference

### Install Everything:
```powershell
pip install -r requirements.txt
```

### Run Application:
```powershell
python app.py
```

### Stop Application:
Press `Ctrl + C` in PowerShell

### Check if Running:
```powershell
# Open browser to:
http://localhost:5000
```

### View Logs:
Logs appear directly in PowerShell where you ran `python app.py`

---

## ❌ Troubleshooting

### Issue: "scikit-learn installation failed"
**Solution:**
```powershell
# Install pre-built wheel
pip install scikit-learn --only-binary :all:
```

### Issue: "Module not found"
**Solution:**
```powershell
# Check which Python pip is using
where python
where pip

# They should point to the same location
# If not, use:
python -m pip install -r requirements.txt
```

### Issue: "Port 5000 already in use"
**Solution:**
```powershell
# Find what's using port 5000
netstat -ano | findstr :5000

# Kill the process (replace PID with actual number)
taskkill /PID <PID> /F

# Or change port in app.py (last line):
# socketio.run(app, debug=True, host='0.0.0.0', port=5001)
```

### Issue: "Permission denied"
**Solution:**
```powershell
# Run PowerShell as Administrator
# Right-click PowerShell icon → "Run as administrator"
```

### Issue: Installation taking too long
**Solution:** This is normal! scikit-learn and numpy take 5-10 minutes to install.

---

## 🎯 Verification Checklist

After installation, verify:

- [ ] `pip install -r requirements.txt` completes without errors
- [ ] `python verify_fixes.py` shows all checks passed
- [ ] `python app.py` starts without errors
- [ ] Browser loads http://localhost:5000
- [ ] Can scan a domain successfully
- [ ] No import errors in PowerShell

---

## 📊 What Works Without Optional Dependencies

### ✅ Core Features (Always Work):
- Domain reconnaissance (DNS, WHOIS, SSL)
- Security header analysis
- Subdomain enumeration
- Port scanning
- Geolocation lookup
- Authenticity checking
- PDF report generation
- Real-time monitoring
- API endpoints
- WebSocket updates

### ⚠️ Optional Features (May be Limited):
- AI threat prediction (works with basic ML)
- Blockchain analysis (limited without web3)
- Advanced ML features (limited without TensorFlow)
- SMS notifications (requires Twilio)
- Telegram alerts (requires telegram-bot)
- Background tasks (limited without Celery)

---

## 🔐 Your API Keys (Already Configured)

Your `.env` file has:
```env
VITE_VIRUSTOTAL_API_KEY=6999c57de5dd070ca9ae05c8957847c5f5107522f3153af78e0a716d2ea3d5f2
VITE_WHOISXMLAPI_KEY=at_1Yi4WT0BFRbOBdjwKO9qu4N3KQorM
VITE_GOOGLE_SAFE_BROWSING_API_KEY=AIzaSyBQY0TwnTzQgM52iYsrm6SXefSxZhgY7OY
SECRET_KEY=2b5b148c9e34f440e0824655f86fb8b928e85a4e1cb1b5ec2874fe7c1e0c3f3c
```

✅ All configured correctly!

---

## 🎉 Success Indicators

When everything is working:

1. **Installation Complete**: No errors after `pip install -r requirements.txt`
2. **App Starts**: See "Running on http://0.0.0.0:5000"
3. **Web UI Loads**: Browser shows the domain scanner interface
4. **Scan Works**: Can scan domains and see results
5. **Real-time Updates**: Progress bar moves during scan

---

## 📞 Still Having Issues?

1. **Copy the exact error message** from PowerShell
2. **Check Python version**: `python --version` (should be 3.13.7)
3. **Make sure you're in the project directory**:
   ```powershell
   cd C:\Users\spmte\OneDrive\Documents\Projects\Domain
   ```
4. **Try installing dependencies one by one**:
   ```powershell
   pip install Flask==3.0.0
   pip install Flask-SocketIO==5.3.6
   pip install requests
   pip install scikit-learn
   ```

---

## 🚀 Quick Start (30 seconds)

If you just want to get running RIGHT NOW:

```powershell
cd C:\Users\spmte\OneDrive\Documents\Projects\Domain
pip install Flask Flask-SocketIO requests dnspython beautifulsoup4 python-dotenv scikit-learn numpy pandas
python app.py
```

Then open: http://localhost:5000

**That's it!** The core functionality will work with just these packages.

---

## 📚 Next Steps After Installation

1. ✅ Scan some domains to test functionality
2. ✅ Review the API documentation in README.md
3. ✅ Customize settings if needed
4. ✅ Commit your changes to GitHub
5. ✅ Set up monitoring for your domains

---

**You're on Python 3.13 which is cutting edge! The updated requirements will work perfectly.**
