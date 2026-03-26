from flask import Flask, request, jsonify
import requests
import dns.resolver
import re
import json
import struct
import math
import hashlib
import os
import io
from datetime import datetime
from collections import Counter

app = Flask(__name__)

# ════════════════════════════════════════════════════════
# Load Parent Configurations
# ════════════════════════════════════════════════════════
CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'parent_config.json')

def load_config():
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)

# ════════════════════════════════════════════════════════
# Static Settings
# ════════════════════════════════════════════════════════
GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyBS8HoM7ygS9hZblXmqDXAHcxapPgatwbI"
MY_SECRET_KEY = "zahraa-secret-2026"

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".click", ".link", ".zip", ".mov",
    ".icu", ".monster", ".gdn", ".biz", ".country", ".stream"
]

BAD_KEYWORDS = ["porn", "sex", "bet", "casino", "dating", "poker", "nude", "xxx", "fuck"]

TRUSTED_DOMAINS = [
    'google', 'microsoft', 'apple', 'cloudflare', 'akamai',
    'github', 'stackoverflow', 'wikipedia'
]

# ════════════════════════════════════════════════════════
# Magic Bytes: Real File Signatures
# ════════════════════════════════════════════════════════
MAGIC_SIGNATURES = {
    # Executables
    b'\x4D\x5A':                         ('exe/dll', True),   # MZ header - Windows PE
    b'\x7FELF':                          ('elf',     True),   # Linux ELF
    b'\xCA\xFE\xBA\xBE':                 ('java',    True),   # Java class / Mach-O
    b'\xCE\xFA\xED\xFE':                 ('macho',   True),   # Mach-O 32-bit
    b'\xCF\xFA\xED\xFE':                 ('macho',   True),   # Mach-O 64-bit
    b'PK\x03\x04':                       ('zip',     False),  # ZIP (could be APK/JAR)
    b'\x50\x4B\x05\x06':                  ('zip',     False),

    # Scripts
    b'#!/':                               ('script',  True),   # Unix shebang
    b'<script':                          ('html_script', True),

    # Documents (Relatively safe)
    b'%PDF':                              ('pdf',     False),
    b'\xD0\xCF\x11\xE0':                 ('ms_office', False), # Old DOC/XLS/PPT
    b'PK':                                ('office_xml', False), # DOCX/XLSX/PPTX

    # Images (Safe)
    b'\xFF\xD8\xFF':                      ('jpeg',    False),
    b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': ('png',     False),
    b'GIF87a':                            ('gif',     False),
    b'GIF89a':                            ('gif',     False),
    b'RIFF':                              ('riff',    False),  # WAV/AVI
    b'\x1A\x45\xDF\xA3':                 ('webm',    False),
}

# ════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════
def log_status(domain, status, reason=""):
    time_str = datetime.now().strftime("%H:%M:%S")
    icon = "✅ ALLOW" if status else "⛔ BLOCK"
    msg = f"[{time_str}] {icon}: {domain.ljust(40)}"
    if reason:
        msg += f" | Reason: {reason}"
    print(msg)

def log_file(filename, status, reason=""):
    time_str = datetime.now().strftime("%H:%M:%S")
    icon = "✅ FILE-OK" if status else "⛔ FILE-BLOCK"
    print(f"[{time_str}] {icon}: {filename.ljust(40)} | {reason}")

def auth_required(req):
    return req.headers.get("X-API-KEY") == MY_SECRET_KEY

# ════════════════════════════════════════════════════════
# Check 1: Blocked Applications (App → Domain)
# ════════════════════════════════════════════════════════
def check_blocked_apps(domain):
    """If the parent blocks an app, its associated domain is also blocked"""
    try:
        config = load_config()
        for app_entry in config.get('blocked_apps', []):
            for blocked_domain in app_entry.get('domains', []):
                # Check for full match or subdomain
                clean_blocked = blocked_domain.replace('www.', '')
                clean_domain  = domain.replace('www.', '')
                if clean_domain == clean_blocked or clean_domain.endswith('.' + clean_blocked):
                    return True, f"App {app_entry['name']} is blocked by parent"
    except Exception as e:
        print(f"Config error: {e}")
    return False, ""

# ════════════════════════════════════════════════════════
# Check 2: Suspicious Patterns (Heuristic)
# ════════════════════════════════════════════════════════
def is_suspicious_pattern(domain):
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        return True, "Suspicious TLD Extension"

    if domain.count('.') > 2:
        if any(t in domain for t in TRUSTED_DOMAINS):
            return False, ""
        return True, "Excessive Subdomains (Phishing Pattern)"

    main_part = domain.split('.')[0]
    if len(main_part) > 12 and re.search(r'[0-9].*[a-z]|[a-z].*[0-9]', main_part):
        if not any(t in domain for t in TRUSTED_DOMAINS):
            return True, "Randomized Bot-like Domain"

    if any(word in domain for word in BAD_KEYWORDS):
        return True, "Inappropriate Content Keyword"

    return False, ""

# ════════════════════════════════════════════════════════
# Check 3: Google Safe Browsing
# ════════════════════════════════════════════════════════
def check_google_reputation(domain):
    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {"clientId": "family-monitor", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": f"http://{domain}/"}, {"url": domain}]
        }
    }
    try:
        response = requests.post(url, json=payload, timeout=2)
        if response.status_code == 200:
            result = response.json()
            if "matches" in result:
                return False, f"Google Flag: {result['matches'][0]['threatType']}"
        return True, ""
    except:
        return True, ""

# ════════════════════════════════════════════════════════
# Deep Content Inspection - 7 Layers
# ════════════════════════════════════════════════════════

# ── Layer 1: Magic Bytes ──────────────────────────────────
def detect_real_type(file_bytes):
    """
    Detect real file type from the first bytes.
    Detects if a file is named photo.jpg but contains an EXE.
    """
    for signature, (file_type, is_dangerous) in MAGIC_SIGNATURES.items():
        if file_bytes[:len(signature)] == signature:
            return file_type, is_dangerous

    # Additional check: MZ header might be at a different offset (some droppers)
    if b'\x4D\x5A' in file_bytes[:512]:
        return 'hidden_exe', True

    return 'unknown', False


# ── Layer 2: PE Header Analysis (for EXE/DLL) ─────────────
def analyze_pe_header(file_bytes):
    """
    Deep scan of PE header to detect:
    - Is the file actually executable?
    - Are there suspicious sections?
    - Is there UPX packing (often malware)?
    """
    issues = []
    try:
        if file_bytes[:2] != b'\x4D\x5A':
            return issues

        # PE offset is located at offset 0x3C
        pe_offset = struct.unpack('<I', file_bytes[0x3C:0x40])[0]
        if pe_offset + 4 > len(file_bytes):
            return issues

        pe_sig = file_bytes[pe_offset:pe_offset + 4]
        if pe_sig != b'PE\x00\x00':
            issues.append('Invalid PE signature - manipulated file')
            return issues

        # Check for UPX packing
        if b'UPX' in file_bytes[:min(len(file_bytes), 1024)]:
            issues.append('File is compressed with UPX (common malware technique)')

        # Check for suspicious section names
        suspicious_sections = [b'.evil', b'.vmp', b'.themida', b'execut']
        for sec in suspicious_sections:
            if sec in file_bytes:
                issues.append(f'Suspicious Section: {sec.decode("utf-8", errors="ignore")}')

        # Check for dangerous strings inside the PE
        dangerous_strings = [
            b'CreateRemoteThread',  # code injection
            b'VirtualAllocEx',      # memory injection
            b'WriteProcessMemory',  # process injection
            b'ShellExecute',        # execute commands
            b'WinExec',             # execute commands
            b'URLDownloadToFile',   # download & execute
            b'RegSetValueEx',       # registry modification
            b'IsDebuggerPresent',   # anti-debugging
            b'NtSetInformationThread',  # anti-debugging
        ]
        found_dangerous = []
        for ds in dangerous_strings:
            if ds in file_bytes:
                found_dangerous.append(ds.decode('utf-8', errors='ignore'))

        if len(found_dangerous) >= 3:
            issues.append(f'Dangerous API calls: {", ".join(found_dangerous[:3])}')

    except Exception as e:
        print(f'PE analysis error: {e}')

    return issues


# ── Layer 3: ZIP/APK/JAR Deep Scan ───────────────────────
def check_zip_contents(file_bytes):
    """
    Full scan inside ZIP:
    - Dangerous filenames
    - Magic Bytes for every internal file
    - Dangerous text content (EICAR, scripts)
    - APK detection
    """
    dangerous_found = []
    try:
        import zipfile

        # EICAR signature - Anti-virus test standard
        EICAR_SIGNATURE = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}'

        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            for name in zf.namelist():
                ext = name.split('.')[-1].lower()

                # ── Dangerous Extensions ──────────────────────
                if ext in ['exe', 'dll', 'bat', 'sh', 'dex', 'so',
                           'ps1', 'vbs', 'js', 'jar', 'cmd', 'hta', 'wsf']:
                    dangerous_found.append(f'Dangerous file inside ZIP: {name}')

                # APK detection
                if name == 'classes.dex':
                    dangerous_found.append('Hidden APK inside ZIP')

                # ── Physical content check for each file ──────────
                try:
                    inner_bytes = zf.read(name)

                    # EICAR test file
                    if EICAR_SIGNATURE in inner_bytes:
                        dangerous_found.append(f'EICAR malware signature in: {name}')
                        continue

                    # Magic Bytes
                    inner_type, inner_dangerous = detect_real_type(inner_bytes)
                    if inner_dangerous:
                        dangerous_found.append(f'{name} real type is dangerous: {inner_type}')
                        continue

                    # Dangerous text content
                    if len(inner_bytes) < 1_000_000:
                        text = inner_bytes.decode('utf-8', errors='ignore').lower()
                        danger_patterns = [
                            ('powershell', 'PowerShell command'),
                            ('invoke-expression', 'PowerShell IEX'),
                            ('cmd.exe /c', 'CMD execution'),
                            ('wscript.shell', 'WScript shell'),
                            ('createremotethread', 'Process injection'),
                            ('virtualalloc', 'Memory injection'),
                            ('urldownloadtofile', 'Download & Execute'),
                            ('curl | bash', 'Curl pipe shell'),
                            ('wget -o- | sh', 'Wget pipe shell'),
                        ]
                        for pattern, label in danger_patterns:
                            if pattern in text:
                                dangerous_found.append(f'{label} in: {name}')
                                break

                except Exception:
                    pass

    except Exception:
        pass

    return dangerous_found


# ── Layer 4: PDF Deep Analysis ───────────────────────────
def analyze_pdf(file_bytes):
    """
    Deep PDF Scan:
    - Hidden JavaScript (common in exploits)
    - Embedded files
    - Suspicious external links
    - Launch actions
    """
    issues = []
    try:
        text = file_bytes.decode('latin-1', errors='ignore')

        # JavaScript in PDF = High risk
        if '/JavaScript' in text or '/JS' in text:
            issues.append('PDF contains JavaScript (common exploit technique)')

        # Embedded files
        if '/EmbeddedFile' in text:
            issues.append('PDF contains embedded files')

        # Launch action (running external programs)
        if '/Launch' in text:
            issues.append('PDF contains Launch action (executing programs)')

        # Suspicious OpenAction
        if '/OpenAction' in text and '/JavaScript' in text:
            issues.append('PDF runs JavaScript automatically on open')

        # Suspicious external URIs
        suspicious_uri_count = text.count('/URI')
        if suspicious_uri_count > 10:
            issues.append(f'PDF contains {suspicious_uri_count} suspicious external links')

        # AcroForm with JavaScript
        if '/AcroForm' in text and '/JavaScript' in text:
            issues.append('PDF form with JavaScript - potential risk')

    except:
        pass
    return issues


# ── Layer 5: Office Macro Detection ──────────────────────
def check_office_macros(file_bytes):
    """
    Detect Macros in Office files:
    - VBA Macros (Most dangerous)
    - AutoOpen / AutoExec
    - Shell commands
    """
    issues = []
    try:
        import zipfile
        # New Office files (docx, xlsx) are ZIP containers
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            names = zf.namelist()

            # Presence of vbaProject = macros
            if any('vbaProject' in n for n in names):
                issues.append('Office file contains VBA Macros')

                # Read macro and look for dangerous commands
                for name in names:
                    if 'vba' in name.lower():
                        try:
                            macro_bytes = zf.read(name)
                            macro_text  = macro_bytes.decode('latin-1', errors='ignore').lower()
                            danger_cmds = ['shell', 'wscript', 'powershell',
                                          'createobject', 'autoopen', 'autoexec',
                                          'document_open', 'workbook_open']
                            found = [c for c in danger_cmds if c in macro_text]
                            if found:
                                issues.append(f'Macro contains: {", ".join(found)}')
                        except:
                            pass

    except zipfile.BadZipFile:
        # Old Office files (doc, xls) - Scan binary content
        try:
            text = file_bytes.decode('latin-1', errors='ignore').lower()
            if 'autoopen' in text or 'document_open' in text:
                issues.append('Old Office file contains suspicious Auto-macro')
        except:
            pass
    except:
        pass
    return issues


# ── Layer 6: Entropy Analysis ─────────────────────────────
def calculate_entropy(data):
    """
    Entropy = Measure of data randomness.
    Entropy > 7.5 = Encrypted or unusually compressed file = malware sign.
    Images and ZIP files normally have high entropy.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def check_entropy_anomaly(file_bytes, real_type):
    """
    Check Entropy considering file type.
    """
    # Types where high entropy is normal
    naturally_high = ('zip', 'office_xml', 'jpeg', 'png', 'gif',
                      'pdf', 'riff', 'webm', 'unknown')

    # Scan the first 4KB
    entropy = calculate_entropy(file_bytes[:4096])

    # Also scan the middle of the file (malware often places payload in the middle)
    mid = len(file_bytes) // 2
    mid_entropy = calculate_entropy(file_bytes[mid:mid + 4096])

    max_entropy = max(entropy, mid_entropy)

    if max_entropy > 7.8 and real_type not in naturally_high:
        return True, f'Very suspicious Entropy ({max_entropy:.2f}/8.0) - likely encrypted malware'

    return False, f'Normal Entropy ({max_entropy:.2f})'


# ── Layer 7: Script & Text Content Analysis ───────────────
def analyze_text_content(file_bytes):
    """
    Scan text files, HTML, and Scripts.
    Detects:
    - Obfuscated JavaScript
    - PowerShell commands
    - Base64 encoded payloads
    - Reverse shells
    """
    issues = []
    try:
        text = file_bytes.decode('utf-8', errors='ignore').lower()

        patterns = [
            # Dangerous PowerShell
            (r'powershell\s+-\w*e[nc]*\w*\s+[a-z0-9+/=]{20,}', 'PowerShell encoded command'),
            (r'invoke-expression|iex\s*\(', 'PowerShell IEX (code execution)'),
            (r'downloadstring|downloadfile', 'PowerShell download & execute'),

            # Malicious JavaScript
            (r'eval\s*\(\s*(?:unescape|atob|string\.fromcharcode)', 'JS obfuscation'),
            (r'document\.write\s*\(\s*unescape', 'JS write obfuscated content'),
            (r'(?:var|let|const)\s+\w+\s*=\s*["\'][a-z0-9+/=]{100,}["\']', 'Large base64 payload'),

            # Reverse shell patterns
            (r'bash\s+-i\s*>&?\s*/dev/tcp/', 'Reverse shell command'),
            (r'nc\s+-e\s*/bin/', 'Netcat reverse shell'),
            (r'python\s+-c\s*["\']import socket', 'Python reverse shell'),

            # Windows malicious
            (r'cmd\.exe\s*/[ck]\s+', 'CMD execution'),
            (r'wscript\.shell', 'WScript shell execution'),
            (r'regsvr32\s+/s\s+/n\s+/u', 'Regsvr32 bypass'),

            # Linux malicious
            (r'chmod\s+\+x.*&&', 'chmod + execute chain'),
            (r'curl.*\|\s*(?:bash|sh)', 'Curl pipe to shell'),
            (r'wget.*-O.*&&\s*(?:bash|sh|\.\/)', 'Wget execute'),
        ]

        for pattern, label in patterns:
            if re.search(pattern, text):
                issues.append(label)

    except:
        pass
    return issues


# ── VirusTotal Hash Check ─────────────────────────────────
def check_virustotal_hash(file_bytes):
    try:
        config = load_config()
        vt_key = config.get('virustotal_api_key', '')
        if not vt_key or vt_key == 'YOUR_API_KEY_HERE':
            return None, "VirusTotal: Not activated"

        sha256 = hashlib.sha256(file_bytes).hexdigest()
        resp = requests.get(
            f'https://www.virustotal.com/api/v3/files/{sha256}',
            headers={'x-apikey': vt_key}, timeout=5
        )

        if resp.status_code == 200:
            stats = resp.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious  = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            if malicious > 0:
                return False, f'VirusTotal: {malicious} engines detected as malware'
            if suspicious > 2:
                return False, f'VirusTotal: {suspicious} suspicious engines'
            return True, f'VirusTotal: Clean ({stats.get("harmless", 0)} engines)'

        elif resp.status_code == 404:
            return None, 'VirusTotal: New/Unknown file'
        return None, f'VirusTotal: error {resp.status_code}'

    except Exception as e:
        return None, f'VirusTotal: {str(e)}'


# ════════════════════════════════════════════════════════
# Comprehensive Scan - Aggregating all layers
# ════════════════════════════════════════════════════════
def scan_file_content(file_bytes, filename, content_length=0):
    """
    Smart scan on the first 1MB only - fast and effective.
    Magic Bytes + PE Header + EICAR are all within the first few KB.
    """
    result  = {'allowed': True, 'reason': '', 'details': []}
    config  = load_config()
    max_mb  = config.get('max_file_size_mb', 50)
    total   = content_length or len(file_bytes)

    print(f'\n{"─"*50}')
    print(f'🔬 Smart Scan: {filename} | scanned={len(file_bytes)/1024:.1f}KB | total={total/1024/1024:.2f}MB')

    # ── Total Size Check ───────────────────────────────────
    if total > max_mb * 1024 * 1024:
        result['allowed'] = False
        result['reason']  = f'File is larger than {max_mb}MB ({total/1024/1024:.1f}MB)'
        print(f'❌ File too large')
        return result

    # ════════════════════════════════════════════════════
    # Layer 1: Magic Bytes - Real Type
    # ════════════════════════════════════════════════════
    real_type, is_dangerous = detect_real_type(file_bytes)
    result['details'].append(f'Real type: {real_type}')
    print(f'[1] Magic Bytes → {real_type} | dangerous={is_dangerous}')

    if is_dangerous:
        result['allowed'] = False
        result['reason']  = f'Actual file content is dangerous ({real_type}) even if extension differs'
        print(f'❌ Dangerous real type: {real_type}')
        return result

    # ════════════════════════════════════════════════════
    # Layer 2: PE Header (If file is hidden EXE/DLL)
    # ════════════════════════════════════════════════════
    if real_type in ('exe/dll', 'hidden_exe'):
        pe_issues = analyze_pe_header(file_bytes)
        result['details'] += pe_issues
        print(f'[2] PE Analysis → {pe_issues or "clean"}')
        if pe_issues:
            result['allowed'] = False
            result['reason']  = f'PE Analysis: {pe_issues[0]}'
            return result

    # ════════════════════════════════════════════════════
    # Layer 3: ZIP/APK Deep Scan
    # ════════════════════════════════════════════════════
    if real_type in ('zip', 'office_xml'):
        zip_issues = check_zip_contents(file_bytes)
        result['details'] += zip_issues
        print(f'[3] ZIP Contents → {zip_issues or "clean"}')
        if zip_issues:
            result['allowed'] = False
            result['reason']  = zip_issues[0]
            return result

    # ════════════════════════════════════════════════════
    # Layer 4: PDF Deep Analysis
    # ════════════════════════════════════════════════════
    if real_type == 'pdf':
        pdf_issues = analyze_pdf(file_bytes)
        result['details'] += pdf_issues
        print(f'[4] PDF Analysis → {pdf_issues or "clean"}')
        if pdf_issues:
            result['allowed'] = False
            result['reason']  = f'Suspicious PDF: {pdf_issues[0]}'
            return result

    # ════════════════════════════════════════════════════
    # Layer 5: Office Macro Detection
    # ════════════════════════════════════════════════════
    if real_type in ('ms_office', 'office_xml', 'zip'):
        macro_issues = check_office_macros(file_bytes)
        result['details'] += macro_issues
        print(f'[5] Office Macros → {macro_issues or "clean"}')
        if macro_issues:
            result['allowed'] = False
            result['reason']  = f'Office: {macro_issues[0]}'
            return result

    # ════════════════════════════════════════════════════
    # Layer 6: Entropy Analysis
    # ════════════════════════════════════════════════════
    is_anomaly, entropy_msg = check_entropy_anomaly(file_bytes, real_type)
    result['details'].append(entropy_msg)
    print(f'[6] Entropy → {entropy_msg}')
    if is_anomaly:
        result['allowed'] = False
        result['reason']  = entropy_msg
        return result

    # ════════════════════════════════════════════════════
    # Layer 7: Text/Script Content Analysis
    # ════════════════════════════════════════════════════
    text_issues = analyze_text_content(file_bytes)
    result['details'] += text_issues
    print(f'[7] Script Analysis → {text_issues or "clean"}')
    if text_issues:
        result['allowed'] = False
        result['reason']  = f'Dangerous content in file: {text_issues[0]}'
        return result

    # ════════════════════════════════════════════════════
    # VirusTotal Hash (Last step - additional confirmation)
    # ════════════════════════════════════════════════════
    vt_ok, vt_msg = check_virustotal_hash(file_bytes)
    result['details'].append(vt_msg)
    print(f'[VT] VirusTotal → {vt_msg}')
    if vt_ok is False:
        result['allowed'] = False
        result['reason']  = vt_msg
        return result

    print(f'✅ All layers passed - File is SAFE')
    print(f'{"─"*50}\n')
    result['reason'] = 'File is clean - passed all inspection layers'
    return result

# ════════════════════════════════════════════════════════
# API Routes
# ════════════════════════════════════════════════════════

# ── Route 1: Domain Safety Check ─────────────────────────────
@app.route("/check-safety", methods=["POST"])
def check_safety():
    if not auth_required(request):
        return jsonify({"allowed": False}), 401

    data   = request.get_json() or {}
    domain = data.get("domain", "").strip().lower().strip('.')

    if not domain or "." not in domain:
        return jsonify({"allowed": True})

    # Phase 0: Blocked applications check
    is_app_blocked, reason = check_blocked_apps(domain)
    if is_app_blocked:
        log_status(domain, False, reason)
        return jsonify({"allowed": False, "reason": reason})

    # Phase 1: Suspicious patterns
    is_bad, reason = is_suspicious_pattern(domain)
    if is_bad:
        log_status(domain, False, reason)
        return jsonify({"allowed": False, "reason": reason})

    # Phase 2: Cloudflare Family DNS
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["1.1.1.3"]
        resolver.timeout = 1.0
        resolver.resolve(domain, "A")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        log_status(domain, False, "Cloudflare Family Block")
        return jsonify({"allowed": False, "reason": "Family DNS Filter"})
    except:
        pass

    # Phase 3: Google Safe Browsing
    is_safe, reason = check_google_reputation(domain)
    if not is_safe:
        log_status(domain, False, reason)
        return jsonify({"allowed": False, "reason": reason})

    log_status(domain, True)
    return jsonify({"allowed": True})


# ── Route 2: File Scan (Before Download) ────────────────
@app.route("/scan-file", methods=["POST"])
def scan_file():
    if not auth_required(request):
        return jsonify({"allowed": False}), 401

    # File comes as multipart or as URL
    data = request.get_json() or {}
    file_url      = data.get('url', '')
    filename      = data.get('filename', 'unknown')
    content_type  = data.get('content_type', '')

    if not file_url:
        return jsonify({"allowed": False, "reason": "File URL not sent"})

    # ── Download file to server for scanning ───────────────────
    print(f"\n📥 Scanning file: {filename} | {file_url[:80]}")

    try:
        config     = load_config()
        max_mb     = config.get('max_file_size_mb', 50)
        max_bytes  = max_mb * 1024 * 1024

        resp = requests.get(
            file_url,
            timeout=30,
            stream=True,
            headers={'User-Agent': 'Mozilla/5.0'}
        )

        # ── Check real Content-Type ─────────────────────
        content_type        = resp.headers.get('Content-Type', '').lower()
        content_disposition = resp.headers.get('Content-Disposition', '').lower()
        content_length      = int(resp.headers.get('Content-Length', 0))

        print(f"   📋 Content-Type: {content_type}")
        print(f"   📎 Content-Disposition: {content_disposition or 'none'}")
        print(f"   📏 Content-Length: {content_length/1024:.1f} KB")

        # If link returns HTML and no content-disposition = not a real file
        if 'text/html' in content_type and 'attachment' not in content_disposition:
            log_file(filename, False, 'Link is an HTML page, not a real file')
            return jsonify({
                "allowed": False,
                "reason": "This link is not a direct download - it is a normal web page"
            })

        # ── Smart Partial Download ────────────────────────
        # Download first 1MB only - sufficient for all checks:
        # Magic Bytes: first 8 bytes
        # PE Header:   first 512 bytes
        # EICAR:       first 128 bytes
        # Entropy:     first 4KB
        # Scripts:     first 1MB
        # ZIP: requires first 1MB + last 64KB (Central Directory)
        PARTIAL_SIZE = 1 * 1024 * 1024  # 1MB

        file_bytes = b''
        for chunk in resp.iter_content(chunk_size=65536):
            file_bytes += chunk
            if len(file_bytes) >= PARTIAL_SIZE:
                print(f"   ✂️  Partial scan: stopped at 1MB (file is {content_length/1024/1024:.1f}MB)")
                break

        print(f"   📦 Bytes downloaded for scan: {len(file_bytes)/1024:.1f} KB")

        # ── Comprehensive Scan ──────────────────────────────────
        result = scan_file_content(file_bytes, filename, content_length)
        log_file(filename, result['allowed'], result['reason'])

        print(f"   📊 Details: {' | '.join(result['details'])}")

        return jsonify({
            "allowed": result['allowed'],
            "reason":  result['reason'],
            "details": result['details']
        })

    except requests.exceptions.Timeout:
        return jsonify({"allowed": False, "reason": "File download for scanning timed out"})
    except Exception as e:
        print(f"   ❌ Scan error: {e}")
        return jsonify({"allowed": False, "reason": f"Scan error: {str(e)}"})


# ── Route 3: Blocked App Management (For Parent) ─────────
@app.route("/parent/blocked-apps", methods=["GET"])
def get_blocked_apps():
    if not auth_required(request):
        return jsonify({}), 401
    config = load_config()
    return jsonify(config.get('blocked_apps', []))

@app.route("/parent/block-app", methods=["POST"])
def block_app():
    if not auth_required(request):
        return jsonify({}), 401

    data = request.get_json() or {}
    config = load_config()

    new_app = {
        "name":    data.get('name', ''),
        "package": data.get('package', ''),
        "domains": data.get('domains', [])
    }

    # Avoid duplication
    existing = [a['package'] for a in config['blocked_apps']]
    if new_app['package'] not in existing:
        config['blocked_apps'].append(new_app)
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=2)

    return jsonify({"success": True, "message": f"Blocked {new_app['name']}"})

@app.route("/parent/unblock-app", methods=["POST"])
def unblock_app():
    if not auth_required(request):
        return jsonify({}), 401

    data    = request.get_json() or {}
    package = data.get('package', '')
    config  = load_config()

    config['blocked_apps'] = [
        a for a in config['blocked_apps'] if a['package'] != package
    ]

    with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

    return jsonify({"success": True})


# ── Route 4: Local File Scan (From Downloads folder) ────────
@app.route("/scan-local-file", methods=["POST"])
def scan_local_file():
    """
    Receives file as base64 from the app and scans it using the same 7 layers.
    For files already in Downloads, not URLs.
    """
    if not auth_required(request):
        return jsonify({"allowed": False}), 401

    data     = request.get_json() or {}
    filename = data.get('filename', 'unknown')
    content  = data.get('content',  '')   # base64
    size     = data.get('size',     0)

    print(f"\n📂 Local Scan: {filename} ({size/1024:.1f} KB)")

    if not content:
        return jsonify({"allowed": False, "reason": "File content not sent"})

    try:
        import base64
        file_bytes = base64.b64decode(content)
    except Exception as e:
        return jsonify({"allowed": False, "reason": f"Decoding error: {str(e)}"})

    config = load_config()
    max_mb = config.get('max_file_size_mb', 50)

    if size > max_mb * 1024 * 1024:
        return jsonify({
            "allowed": False,
            "reason":  f"File is larger than {max_mb}MB"
        })

    result = scan_file_content(file_bytes, filename, content_length=size)
    log_file(filename, result['allowed'], result['reason'])

    return jsonify({
        "allowed": result['allowed'],
        "reason":  result['reason'],
        "details": result['details']
    })


# ════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("\n" + "═"*60)
    print("🛡️  Family Monitor PRO - Advanced Protection Active")
    print("📡 Domain filtering + App blocking + File scanning")
    print("═"*60 + "\n")
    app.run(host="0.0.0.0", port=9000, threaded=True)