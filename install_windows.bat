@echo off
echo ============================================================
echo   Domain Reconnaissance Tool - Windows Installation
echo ============================================================
echo.

echo Step 1: Checking Python version...
python --version
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Python not found! Please install Python 3.13
    pause
    exit /b 1
)
echo.

echo Step 2: Upgrading pip...
python -m pip install --upgrade pip
echo.

echo Step 3: Installing dependencies...
echo This will take 5-10 minutes. Please be patient...
pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: Installation failed!
    echo Trying minimal installation...
    pip install Flask Flask-SocketIO requests dnspython beautifulsoup4 python-dotenv scikit-learn numpy pandas python-whois reportlab networkx plotly flask-restful flask-limiter flask-cors simple-websocket python-engineio python-socketio
)
echo.

echo Step 4: Verifying installation...
python verify_fixes.py
echo.

echo ============================================================
echo   Installation Complete!
echo ============================================================
echo.
echo To start the application:
echo   python app.py
echo.
echo Then open your browser to:
echo   http://localhost:5000
echo.
echo Press any key to exit...
pause >nul
