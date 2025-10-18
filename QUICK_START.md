# Quick Start Guide

## 🚀 Get Running in 5 Minutes

### Step 1: Setup Environment (1 min)
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### Step 2: Install Dependencies (2 min)
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Configure (1 min)
```bash
# Copy environment template
cp .env.example .env

# Edit .env and add your API keys (optional for testing)
# The app will work with limited functionality without keys
```

### Step 4: Run (1 min)
```bash
python app.py
```

Open browser: **http://localhost:5000**

---

## ✅ What Was Fixed

| Issue | Status |
|-------|--------|
| MimeText import error | ✅ Fixed |
| Greenlet threading error | ✅ Fixed |
| API decorator issues | ✅ Fixed |
| Dependencies updated | ✅ Fixed |

---

## 🧪 Quick Test

```bash
# Test imports work
python -c "from real_time_monitor import real_time_monitor; print('OK')"

# Test app starts
python app.py
# Press Ctrl+C to stop when you see it's running
```

---

## 📦 Git Commands

```bash
# Add all changes
git add .

# Commit
git commit -m "Fix: Resolved all import and threading errors"

# Push
git push origin main
```

---

## 🎯 Key Changes Made

1. **real_time_monitor.py** - Fixed `MimeText` → `MIMEText`
2. **app.py** - Added `async_mode='threading'` to SocketIO
3. **requirements.txt** - Removed eventlet, added websocket support
4. **api_integration.py** - Fixed decorator initialization

---

## 🔍 Verify Everything Works

1. ✅ No import errors
2. ✅ App starts on port 5000
3. ✅ Web interface loads
4. ✅ Can scan domains
5. ✅ WebSocket connections work

---

## 📞 Need Help?

- Read `SETUP_GUIDE.md` for detailed instructions
- Check `FIX_SUMMARY.md` for technical details
- Review logs if errors occur

---

## ⚡ Features Ready to Use

- ✅ Domain reconnaissance
- ✅ AI threat analysis
- ✅ Real-time monitoring
- ✅ Blockchain scanning
- ✅ Compliance auditing
- ✅ Vulnerability correlation
- ✅ Visual attack mapping
- ✅ Automated workflows
- ✅ REST API
- ✅ WebSocket updates

**Status: Production Ready! 🎉**
