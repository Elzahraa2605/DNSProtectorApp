import React, { useState, useRef, useCallback } from 'react';
import {
  View, TextInput, StyleSheet, Text,
  TouchableOpacity, ActivityIndicator,
} from 'react-native';
import WebView from 'react-native-webview';

const BACKEND_URL = 'http://10.0.2.2:9000/check-safety';
const SECRET_KEY  = 'zahraa-secret-2026';
const HOME_URL    = 'https://www.google.com';

// ── Cache ────────────────────────────────────────────────
const safeCache = new Set<string>([
  'google.com', 'gstatic.com', 'googleapis.com',
  'google.com.eg', 'ggpht.com', 'googleusercontent.com',
  'youtube.com', 'ytimg.com', 'googlevideo.com',
]);
const blockedCache = new Set<string>();

function getHostname(url: string): string {
  try { return new URL(url).hostname.replace(/^www\./, '').toLowerCase(); }
  catch { return ''; }
}

async function checkDomain(host: string): Promise<{ allowed: boolean; reason?: string }> {
  if (safeCache.has(host))    return { allowed: true };
  if (blockedCache.has(host)) return { allowed: false, reason: 'موقع محظور' };

  console.log('[CHECK] ➜', host);
  try {
    const res  = await fetch(BACKEND_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-KEY': SECRET_KEY },
      body: JSON.stringify({ domain: host }),
    });
    const data = await res.json();
    console.log('[SERVER]', host, '→', data.allowed ? '✅ ALLOW' : '⛔ BLOCK', data.reason ?? '');
    if (data.allowed) safeCache.add(host);
    else              blockedCache.add(host);
    return data;
  } catch {
    return { allowed: false, reason: 'تعذر الاتصال بخادم الفحص' };
  }
}

function buildUrl(input: string): string {
  const t = input.trim();
  if (!t) return HOME_URL;
  if (t.startsWith('http://') || t.startsWith('https://')) return t;
  if (t.includes('.')) return `https://${t}`;
  return `https://www.google.com/search?q=${encodeURIComponent(t)}`;
}

export default function SafeBrowser() {
  const [urlBar,     setUrlBar]     = useState(HOME_URL);
  const [currentUrl, setCurrentUrl] = useState(HOME_URL);
  const [isChecking, setIsChecking] = useState(false);
  const [isBlocked,  setIsBlocked]  = useState(false);
  const [blockReason,setBlockReason]= useState('');
  const webViewRef  = useRef<WebView>(null);
  const pendingUrls = useRef<Set<string>>(new Set());

  // ── تحميل URL (من شريط العنوان) ──────────────────────
  const navigateTo = useCallback(async (rawInput: string) => {
    const url  = buildUrl(rawInput);
    const host = getHostname(url);

    if (!host || url.includes('google.com/search')) {
      setIsBlocked(false);
      setCurrentUrl(url);
      return;
    }

    setIsChecking(true);
    setIsBlocked(false);
    const result = await checkDomain(host);
    setIsChecking(false);

    if (result.allowed) {
      setCurrentUrl(url);
    } else {
      setIsBlocked(true);
      setBlockReason(result.reason || 'محتوى غير مناسب');
    }
  }, []);

  // ── فحص الروابط داخل الـ WebView ─────────────────────
  const onShouldStart = useCallback((request: any): boolean => {
    const url: string = request.url;

    if (!url || !url.startsWith('http'))    return true;
    if (request.isTopFrame === false)        return true; // sub-resources

    const host = getHostname(url);
    if (!host)                return true;
    if (safeCache.has(host))  return true;

    if (blockedCache.has(host)) {
      setTimeout(() => { setIsBlocked(true); setBlockReason('موقع محظور'); }, 0);
      return false;
    }

    // مجهول: امنع فوراً وافحص async
    if (pendingUrls.current.has(url)) return false;
    pendingUrls.current.add(url);
    setIsChecking(true);

    checkDomain(host).then((result) => {
      setIsChecking(false);
      pendingUrls.current.delete(url);

      if (result.allowed) {
        webViewRef.current?.injectJavaScript(`window.location.href=${JSON.stringify(url)};true;`);
      } else {
        setIsBlocked(true);
        setBlockReason(result.reason || 'محتوى غير مناسب');
      }
    });

    return false;
  }, []);

  const goHome = useCallback(() => {
    setIsBlocked(false);
    setBlockReason('');
    pendingUrls.current.clear();
    setCurrentUrl(HOME_URL);
    setUrlBar(HOME_URL);
  }, []);

  return (
    <View style={s.container}>

      {/* شريط العنوان البسيط */}
      <View style={s.bar}>
        <TouchableOpacity onPress={() => webViewRef.current?.goBack()} style={s.navBtn}>
          <Text style={s.navTxt}>‹</Text>
        </TouchableOpacity>
        <TouchableOpacity onPress={() => webViewRef.current?.goForward()} style={s.navBtn}>
          <Text style={s.navTxt}>›</Text>
        </TouchableOpacity>

        <TextInput
          style={s.input}
          value={urlBar}
          onChangeText={setUrlBar}
          onSubmitEditing={() => navigateTo(urlBar)}
          autoCapitalize="none"
          autoCorrect={false}
          returnKeyType="go"
          keyboardType="url"
          selectTextOnFocus
        />

        <TouchableOpacity onPress={() => webViewRef.current?.reload()} style={s.navBtn}>
          <Text style={s.navTxt}>↻</Text>
        </TouchableOpacity>
        <TouchableOpacity onPress={goHome} style={s.navBtn}>
          <Text style={s.navTxt}>⌂</Text>
        </TouchableOpacity>
      </View>

      {/* spinner الفحص */}
      {isChecking && (
        <View style={s.overlay}>
          <ActivityIndicator size="large" color="#007AFF" />
          <Text style={s.checkTxt}>🔍 جاري فحص الأمان...</Text>
        </View>
      )}

      {/* شاشة الحظر */}
      {isBlocked ? (
        <View style={s.blockScreen}>
          <Text style={s.blockIcon}>🚫</Text>
          <Text style={s.blockTitle}>الموقع محظور</Text>
          <Text style={s.blockReason}>{blockReason}</Text>
          <TouchableOpacity onPress={goHome} style={s.homeBtn}>
            <Text style={s.homeTxt}>العودة للرئيسية</Text>
          </TouchableOpacity>
        </View>
      ) : (
        <WebView
          ref={webViewRef}
          source={{ uri: currentUrl }}
          style={s.webview}
          onShouldStartLoadWithRequest={onShouldStart}
          onNavigationStateChange={(nav) => { if (nav.url) setUrlBar(nav.url); }}
          javaScriptEnabled
          domStorageEnabled
          startInLoadingState
          onError={(e) => console.warn('WebView error:', e.nativeEvent)}
        />
      )}
    </View>
  );
}

const s = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#fff' },

  // شريط العنوان
  bar: {
    flexDirection: 'row', alignItems: 'center',
    paddingHorizontal: 8, paddingVertical: 10,
    backgroundColor: '#f5f5f5',
    borderBottomWidth: 1, borderBottomColor: '#ddd',
  },
  navBtn: { paddingHorizontal: 12, paddingVertical: 6 },
  navTxt: { fontSize: 32, color: '#007AFF' },
  input: {
    flex: 1, height: 46,
    backgroundColor: '#fff', borderRadius: 12,
    paddingHorizontal: 14, fontSize: 15,
    borderWidth: 1, borderColor: '#ddd',
    marginHorizontal: 6,
  },

  // overlay الفحص
  overlay: {
    position: 'absolute', top: 0, left: 0, right: 0, bottom: 0,
    justifyContent: 'center', alignItems: 'center',
    backgroundColor: 'rgba(255,255,255,0.95)', zIndex: 10,
  },
  checkTxt: { marginTop: 14, fontSize: 15, color: '#333' },

  webview: { flex: 1 },

  // شاشة الحظر
  blockScreen: {
    flex: 1, justifyContent: 'center', alignItems: 'center',
    backgroundColor: '#fff5f5', padding: 30,
  },
  blockIcon:   { fontSize: 72, marginBottom: 16 },
  blockTitle:  { fontSize: 26, fontWeight: 'bold', color: '#d00', marginBottom: 10 },
  blockReason: { fontSize: 15, color: '#555', textAlign: 'center', marginBottom: 30 },
  homeBtn: {
    backgroundColor: '#4CAF50', paddingVertical: 12,
    paddingHorizontal: 32, borderRadius: 24,
  },
  homeTxt: { color: '#fff', fontSize: 16, fontWeight: 'bold' },
});