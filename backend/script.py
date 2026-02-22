from flask import Flask, request, jsonify

import requests

import dns.resolver

import re

from datetime import datetime



app = Flask(__name__)



# ────────────────────────────────────────────────

# Configuration - الإعدادات

# ────────────────────────────────────────────────

GOOGLE_SAFE_BROWSING_API_KEY = " "  # ضع مفتاح API الخاص بك هنا

MY_SECRET_KEY =  "zahraa-secret-2026"



# 1. قائمة الامتدادات المشبوهة (Suspicious TLDs)

SUSPICIOUS_TLDS = [

    ".xyz", ".top", ".click", ".link", ".zip", ".mov",

    ".icu", ".monster", ".gdn", ".biz", ".country", ".stream"

]



# 2. الكلمات الدلالية المحظورة (Heuristic Keywords)

BAD_KEYWORDS = ["porn", "sex", "bet", "casino", "dating", "poker", "nude", "xxx", "fuck"]



# 3. المواقع الموثوقة (Whitelisted for Subdomains)

TRUSTED_DOMAINS = [

    'google', 'microsoft', 'apple', 'facebook', 'cloudflare', 'akamai',

    'x.ai', 'grok.com', 'twitter', 't.co', 'twimg', 'instagram', 'github'

]



# ────────────────────────────────────────────────

# Helpers - الدوال المساعدة

# ────────────────────────────────────────────────

def log_status(domain, status, reason=""):

    time_str = datetime.now().strftime("%H:%M:%S")

    icon = "✅ ALLOW" if status else "⛔ BLOCK"

    msg = f"[{time_str}] {icon}: {domain.ljust(35)}"

    if reason:

        msg += f" | السبب: {reason}"

    print(msg)



def is_suspicious_pattern(domain):

    """منطق الهيوريستيك المطور لفحص الأنماط والـ Subdomains"""

   

    # أ- فحص الامتدادات المشبوهة

    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):

        return True, "Suspicious TLD Extension"

   

    # ب- فحص الـ Subdomains العميقة (أكثر من نقطتين)

    if domain.count('.') > 2:

        # لو الدومين فيه كلمة من الموثوقين، بنعديه فوراً في المرحلة دي

        if any(t in domain for t in TRUSTED_DOMAINS):

            return False, ""

        return True, "Excessive Subdomains (Phishing Pattern)"



    # ج- فحص العشوائية (Entropy): حروف وأرقام عشوائية طويلة

    main_part = domain.split('.')[0]

    if len(main_part) > 12 and re.search(r'[0-9].*[a-z]|[a-z].*[0-9]', main_part):

        if not any(t in domain for t in TRUSTED_DOMAINS):

            return True, "Randomized Bot-like Domain"



    # د- فحص الكلمات المحظورة

    if any(word in domain for word in BAD_KEYWORDS):

        return True, "Inappropriate Content Keyword"



    return False, ""



def check_google_reputation(domain):

    """فحص السمعة عبر Google Safe Browsing"""

    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"

    payload = {

        "client": {"clientId": "family-monitor", "clientVersion": "1.0"},

        "threatInfo": {

            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],

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



# ────────────────────────────────────────────────

# API Route - المسار الرئيسي

# ────────────────────────────────────────────────

@app.route("/check-safety", methods=["POST"])

def check_safety():

    if request.headers.get("X-API-KEY") != MY_SECRET_KEY:

        return jsonify({"allowed": False}), 401



    data = request.get_json() or {}

    domain = data.get("domain", "").strip().lower().strip('.')



    # تجاهل الأسماء الناقصة (البحث)

    if not domain or "." not in domain:

        return jsonify({"allowed": True})



    # المرحلة 1: الهيوريستيك (الأنماط والامتدادات)

    is_bad, reason = is_suspicious_pattern(domain)

    if is_bad:

        log_status(domain, False, reason)

        return jsonify({"allowed": False, "reason": reason})



    # المرحلة 2: Cloudflare Family (DNS) لفلترة المحتوى

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



    # المرحلة 3: Google Safe Browsing

    is_safe, reason = check_google_reputation(domain)

    if not is_safe:

        log_status(domain, False, reason)

        return jsonify({"allowed": False, "reason": reason})



    log_status(domain, True)

    return jsonify({"allowed": True})



if __name__ == "__main__":

    print("\n" + "═"*60)

    print("🛡️  Family Monitor PRO - Intelligent Filtering Active")

    print("📡 Monitoring all subdomains and suspicious patterns...")

    print("═"*60 + "\n")

    app.run(host="0.0.0.0", port=9000, threaded=True)

