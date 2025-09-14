# 🛡️ Domain Reconnaissance Web Tool

A comprehensive Python-based web application for domain reconnaissance, threat intelligence, and security analysis. This tool provides detailed insights into domain authenticity, security posture, and potential threats through an intuitive web interface.

![Domain Reconnaissance Tool](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.3+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## 🌟 Features

### 🔍 Comprehensive Domain Analysis
- **WHOIS Information**: Detailed registrar, registrant, and domain lifecycle data
- **DNS Records**: Complete DNS record analysis (A, AAAA, MX, NS, TXT, CNAME)
- **SSL Certificate**: Certificate validation, issuer details, and expiry information
- **Geolocation**: IP-based geographic location with interactive world map
- **Subdomain Discovery**: Automated subdomain enumeration using certificate transparency logs

### 🛡️ Security & Threat Intelligence
- **VirusTotal Integration**: Malware and threat detection using VirusTotal API
- **Google Safe Browsing**: Phishing and malware detection
- **Authenticity Verification**: Advanced algorithms to detect fake/phishing domains
- **Security Headers Analysis**: HTTP security headers evaluation
- **Open Port Scanning**: Common port detection and service identification

### 🌐 Advanced Reconnaissance
- **Technology Stack Detection**: Web technologies and frameworks identification
- **Reverse IP Lookup**: Other domains hosted on the same IP
- **Network Traceroute**: Network path analysis to target domain
- **Email Discovery**: Associated email addresses extraction
- **Wayback Machine**: Historical website snapshots and images

### 🎨 Modern Web Interface
- **Responsive Design**: Mobile-friendly interface with modern UI/UX
- **Dark/Light Theme**: Toggle between themes with persistent preference
- **Interactive Earth Animation**: 3D globe visualization using amCharts
- **Real-time Progress**: Live scan progress with detailed status updates
- **PDF Report Generation**: Comprehensive downloadable reports

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip package manager
- API keys for external services (optional but recommended)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/domain-recon-web.git
cd domain-recon-web
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Configure environment variables**
```bash
cp .env.example .env
# Edit .env with your API keys
```

4. **Run the application**
```bash
python app.py
```

5. **Access the web interface**
Open your browser and navigate to `http://localhost:5000`

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
# Flask Configuration
SECRET_KEY=your-secret-key-here-change-this-in-production

# API Keys (Optional but recommended for full functionality)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
WHOISXMLAPI_KEY=your_whoisxml_api_key_here
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_api_key_here
```

### API Key Setup

#### VirusTotal API
1. Visit [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Create a free account
3. Navigate to your profile and copy the API key
4. Add to `.env` file

#### WHOISXML API
1. Visit [WHOISXML API](https://whoisxmlapi.com/)
2. Sign up for a free account
3. Get your API key from the dashboard
4. Add to `.env` file

#### Google Safe Browsing API
1. Visit [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Safe Browsing API
4. Create credentials and get API key
5. Add to `.env` file

## 📊 Usage

### Web Interface

1. **Enter Domain**: Type the domain name you want to analyze
2. **Start Scan**: Click "Scan Domain" to begin comprehensive analysis
3. **Monitor Progress**: Watch real-time progress updates
4. **View Results**: Explore detailed reconnaissance data
5. **Download Report**: Generate and download PDF report

### API Endpoints

The application also provides REST API endpoints:

```bash
# Start a domain scan
POST /api/scan
{
  "domain": "example.com"
}

# Get scan status
GET /api/scan/{scan_id}/status

# Download PDF report
GET /api/scan/{scan_id}/download
```

## 🏗️ Architecture

### Project Structure
```
domain-recon-web/
├── app.py                 # Main Flask application
├── recon.py              # Reconnaissance engine
├── auth_check.py         # Authenticity verification
├── pdf_generator.py      # PDF report generation
├── templates/
│   └── index.html        # Web interface
├── requirements.txt      # Python dependencies
├── .env                  # Environment variables
└── README.md            # Documentation
```

### Core Components

#### 🔍 Reconnaissance Engine (`recon.py`)
- Modular design with individual functions for each data source
- Caching mechanism to avoid API rate limits
- Fallback strategies for reliable data collection
- Error handling and timeout management

#### 🛡️ Authenticity Checker (`auth_check.py`)
- Multi-source threat intelligence aggregation
- Confidence scoring algorithm
- Known phishing domain detection
- Official domain link suggestions

#### 📄 PDF Generator (`pdf_generator.py`)
- Professional report formatting
- Comprehensive data visualization
- Branded document generation
- Optimized for printing and sharing

#### 🌐 Web Interface (`templates/index.html`)
- Modern responsive design
- Interactive data visualization
- Real-time updates and progress tracking
- Accessibility-compliant interface

## 🎯 Features in Detail

### 🔒 Authenticity Verification
The tool uses advanced algorithms to determine domain authenticity:
- **VirusTotal Analysis**: Checks against 70+ antivirus engines
- **Google Safe Browsing**: Detects phishing and malware sites
- **Domain Reputation**: Historical threat intelligence data
- **Confidence Scoring**: Algorithmic risk assessment (0-100 scale)

### 🌍 Interactive Earth Visualization
- **3D Globe**: Rotating Earth with location markers
- **Geographic Data**: Country, city, ISP, and timezone information
- **Visual Mapping**: Click-to-zoom functionality
- **Responsive Design**: Adapts to different screen sizes

### 📊 Comprehensive Reporting
- **Executive Summary**: High-level findings and recommendations
- **Technical Details**: In-depth technical analysis
- **Visual Charts**: Data visualization and graphs
- **Actionable Insights**: Security recommendations and next steps

## 🔧 Advanced Configuration

### Custom Scanning Profiles
You can customize scanning behavior by modifying the reconnaissance functions:

```python
# Example: Custom port scanning
def get_open_ports(domain: str, custom_ports: list = None) -> list:
    ports = custom_ports or [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
    # ... scanning logic
```

### Performance Optimization
- **Caching**: TTL-based caching for API responses
- **Concurrent Processing**: Parallel data collection
- **Rate Limiting**: Respectful API usage
- **Timeout Management**: Prevents hanging requests

## 🚀 Deployment

### Production Deployment

#### Using Gunicorn
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

#### Using Docker
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

#### Environment Variables for Production
```env
FLASK_ENV=production
SECRET_KEY=your-super-secret-production-key
# ... other API keys
```

### Security Considerations
- **API Key Protection**: Never commit API keys to version control
- **Rate Limiting**: Implement request rate limiting
- **Input Validation**: Sanitize all user inputs
- **HTTPS**: Use SSL/TLS in production
- **Firewall**: Restrict access to necessary ports only

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Commit changes**: `git commit -m 'Add amazing feature'`
4. **Push to branch**: `git push origin feature/amazing-feature`
5. **Open a Pull Request**

### Development Guidelines
- Follow PEP 8 style guidelines
- Add docstrings to all functions
- Include error handling
- Write unit tests for new features
- Update documentation

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **VirusTotal**: For comprehensive threat intelligence
- **WHOISXML API**: For reliable WHOIS data
- **Google Safe Browsing**: For phishing detection
- **amCharts**: For beautiful data visualization
- **Certificate Transparency**: For subdomain discovery
- **Open Source Community**: For various tools and libraries

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/domain-recon-web/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/domain-recon-web/discussions)
- **Email**: support@yourproject.com

## 🔮 Roadmap

### Upcoming Features
- [ ] **Database Integration**: Persistent scan history
- [ ] **User Authentication**: Multi-user support
- [ ] **Scheduled Scans**: Automated periodic scanning
- [ ] **API Rate Limiting**: Built-in rate limiting
- [ ] **Custom Alerts**: Email/SMS notifications
- [ ] **Bulk Scanning**: Multiple domain analysis
- [ ] **Integration APIs**: Webhook support
- [ ] **Mobile App**: Native mobile applications

### Performance Improvements
- [ ] **Async Processing**: Non-blocking scan operations
- [ ] **Redis Caching**: Distributed caching layer
- [ ] **Load Balancing**: Multi-instance deployment
- [ ] **CDN Integration**: Static asset optimization

---

**⭐ Star this repository if you find it useful!**

**🐛 Found a bug? [Report it here](https://github.com/yourusername/domain-recon-web/issues)**

**💡 Have a feature request? [Let us know](https://github.com/yourusername/domain-recon-web/discussions)**