# ==========================================
# Acunetix Configuration
# ==========================================
# Ganti dengan API Key Acunetix Anda (bisa didapatkan di Profile menu Acunetix)
ACUNETIX_API_KEY = "xxxxxxxxxxxxxxxxxxx"

# Host URL Acunetix (default Windows: https://localhost:13443, Linux: https://localhost:3443)
HOST = "https://localhost:13443"

# Jumlah target yang di-scan bersamaan (concurrent)
NUMBER_OF_TARGETS_SIMULTANEOUSLY = 3

# Aktifkan Flask REST API Server pendamping jika diperlukan
API_SERVER = True

# Scanning Profile ID Acunetix.
# Default Acunetix Profiles UUID:
# - Full Scan: '11111111-1111-1111-1111-111111111111'
# - High Risk: '11111111-1111-1111-1111-111111111112'
# - Cross-site Scripting: '11111111-1111-1111-1111-111111111116'
# - SQL Injection: '11111111-1111-1111-1111-111111111113'
# - Crawl Only: '11111111-1111-1111-1111-111111111117'
SCAN_PROFILE_ID = '11111111-1111-1111-1111-111111111111'

# Custom scan profile template (opsional jika ingin membuat profile baru di Acunetix)
SCAN_PROFILE = {
    "name": "AcuScan Auto Profile",
    "custom": True,
    "checks": [
        "wvs/RPA/InsecureTransition.js",
        "wvs/httpdata/mixed_content_over_https.js",
        "wvs/RPA/Cookie_On_Parent_Domain.js",
        "wvs/RPA/Cookie_Without_HttpOnly.js",
        "wvs/RPA/Cookie_Without_Secure.js",
        "wvs/RPA/Cookie_Validator.js",
        "wvs/RPA/SRI_Not_Implemented.js",
        "wvs/Scripts/PerServer/Reverse_Proxy_Bypass.script",
        "wvs/target/RevProxy_Detection.js",
        "wvs/Crawler/HTTPS_insecure_maxTLS.js",
        "wvs/Scripts/PerFile/Javascript_Libraries_Audit.script",
        "wvs/httpdata/javascript_library_audit_external.js",
        "wvs/httpdata/permissions_policy.js",
        "wvs/httpdata/CSP_not_implemented.js",
        "wvs/httpdata/content_security_policy.js",
        "wvs/httpdata/rails_accept_file_content_disclosure.js",
        "wvs/httpdata/X_Frame_Options_not_implemented.js",
        "wvs/httpdata/iframe_sandbox.js",
        "wvs/Scripts/PerServer/SSL_Audit.script",
        "wvs/target/ssltest",
        "wvs/httpdata/HSTS_not_implemented.js",
        "ovas/",
    ],
}

# Vulnerability types to ignore/exclude from notifications
OUT_SCOPE_VULN_ACUNETIX = [
    '26f9af3b-acf6-f3e4-0fdc-567ac9e03527',
    'bca221d1-8581-3375-4097-66b0048ed088',
    '3f6a8a0e-07f2-af81-54ff-61020299caeb',
    '34a6c791-c497-27d5-7272-6a968e9fdccb',  # HTTP Strict Transport Security (HSTS) Policy Not Enabled
    '391f39d7-6805-cd0c-44ec-df4bf71273eb',  # Host header attack
    '84fd0f24-a88f-09cf-97eb-67959deb26d4',  # Vulnerable JavaScript libraries
    'dc80dd1d-735b-4ba7-b279-589743eeba6e',  # WordPress Deserialization of Untrusted Data Vulnerability
    '029afcbb-3ec2-be3c-5cc3-29f5cfe016f4',  # SSL Certificate Is About To Expire
    '253317f4-6382-e8f5-acd2-b69f488adc11',  # WordPress 6.0.x Multiple Vulnerabilities
    '59ec3cbe-d67f-6a74-6aa1-f449d224ab71'   # Vulnerable package dependencies
]

# Time limit per scan target in hours (akan otomatis dihentikan jika melebihi)
SCAN_TIME = 24

# Notifikasi vulnerability real-time via Telegram
NOTIFICATION = False

# ==========================================
# Telegram Configuration
# ==========================================
TELEGRAM_API_KEY = ''

# Telegram User ID yang diizinkan mengirim perintah
ALLOWED_USER_ID = 

# Out of scope untuk scanner nuclei
OUT_SCOPE_VULN_NUCLEI = ['CVE-xxxx-xxxx']

# Port untuk REST API server
API_PORT = 22132

# Token Expiration (detik)
TOKEN_EXPIRATION = 3600  # 1 jam

# Secret key untuk otentikasi JWT API
SECRET_KEY = ''
