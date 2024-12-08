import re
import requests
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

# Configuration (replace with your actual VirusTotal API key)
VIRUSTOTAL_API_KEY = 'ee63dc1a5887836ba49fe4a63fe69d1abeba0c2e6d0f6577fa48143b45326127'

def validate_url(url):
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def check_suspicious_keywords(url):
    """Check for suspicious keywords in the URL"""
    suspicious_keywords = [
        'login', 'secure', 'account', 'verify', 
        'update', 'confirm', 'signin', 'sign-in'
    ]
    url_lower = url.lower()
    
    keyword_matches = [kw for kw in suspicious_keywords if kw in url_lower]
    return keyword_matches

def analyze_url_structure(url):
    """Analyze URL structure for potential red flags"""
    parsed_url = urlparse(url)
    
    # Check number of subdomains
    subdomains = parsed_url.netloc.split('.')
    subdomain_count = len(subdomains) - 2 if len(subdomains) > 2 else 0
    
    # Check for excessive hyphens
    hyphen_count = parsed_url.netloc.count('-')
    
    # Check for IP address instead of domain
    is_ip_address = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed_url.netloc)
    
    return {
        'subdomains': subdomain_count,
        'hyphens': hyphen_count,
        'is_ip_address': bool(is_ip_address)
    }

def check_virustotal(url):
    """Check URL against VirusTotal (requires API key)"""
    try:
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
        params = {'url': url}
        response = requests.get(
            'https://www.virustotal.com/api/v3/urls/analyse', 
            headers=headers, 
            params=params
        )
        data = response.json()
        
        # Analyze VirusTotal results (simplified)
        return data.get('positives', 0) > 2
    except Exception:
        return False

def detect_phishing(url):
    """Main phishing detection logic"""
    # Validate URL first
    if not validate_url(url):
        return {
            'status': 'Invalid',
            'confidence': 0,
            'reason': 'Invalid URL format'
        }
    
    # Initial risk assessment
    risk_score = 0
    reasons = []
    
    # Check suspicious keywords
    keyword_matches = check_suspicious_keywords(url)
    if keyword_matches:
        risk_score += len(keyword_matches) * 10
        reasons.append(f"Suspicious keywords found: {', '.join(keyword_matches)}")
    
    # Analyze URL structure
    url_structure = analyze_url_structure(url)
    if url_structure['subdomains'] > 2:
        risk_score += 20
        reasons.append(f"Excessive subdomains: {url_structure['subdomains']}")
    
    if url_structure['hyphens'] > 2:
        risk_score += 15
        reasons.append(f"Excessive hyphens: {url_structure['hyphens']}")
    
    if url_structure['is_ip_address']:
        risk_score += 25
        reasons.append("URL uses IP address instead of domain name")
    
    # VirusTotal check (optional, requires API key)
    try:
        if check_virustotal(url):
            risk_score += 40
            reasons.append("Flagged by VirusTotal")
    except Exception:
        pass  # If VirusTotal check fails, ignore
    
    # Determine risk level
    if risk_score >= 50:
        status = 'Malicious'
    elif risk_score >= 20:
        status = 'Suspicious'
    else:
        status = 'Safe'
    
    return {
        'status': status,
        'confidence': min(risk_score, 100),
        'reasons': reasons
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check_url', methods=['POST'])
def check_url():
    url = request.json.get('url', '')
    result = detect_phishing(url)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)