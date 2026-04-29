import React, { useState, useRef, useCallback, useEffect } from 'react';
import {
  View, TextInput, StyleSheet, Text,
  ActivityIndicator, TouchableOpacity, Modal, NativeModules,
  NativeEventEmitter, Alert,
} from 'react-native';
import WebView, { WebViewMessageEvent } from 'react-native-webview';

const { FileMonitor } = NativeModules;

const BACKEND_URL = 'http://10.0.2.2:9000';
const SECRET_KEY  = 'zahraa-secret-2026';
const HOME_URL    = 'https://www.google.com';
const HEADERS     = { 'Content-Type': 'application/json', 'X-API-KEY': SECRET_KEY };

// ── امتدادات الملفات (تم إضافة txt لاكتشاف EICAR وحذف php لفتح الصفحات) ──
const DOWNLOAD_EXTENSIONS = [
  'exe','bat','cmd','msi','dll','apk','dex','sh','ps1','vbs','jar','hta','wsf','com','pif','scr',
  'zip','rar','7z','tar','gz','bz2','xz','cab','iso','dmg',
  'bin','dat','pak','out','run','elf','ko','sys','drv',
  'pdf','doc','docx','xls','xlsx','ppt','pptx','odt','ods',
  'mp3','mp4','avi','mov','mkv','flv','wmv','webm',
  'jpg','jpeg','png','gif','bmp','svg','webp','ico',
  'txt' // <-- تم الإضافة هنا عشان ملفات EICAR الوهمية
];

// ── JS يُحقن في كل صفحة ──────────────────────────────
const INTERCEPT_JS = `
(function() {
  var EXTS = ${JSON.stringify(DOWNLOAD_EXTENSIONS)};

  function getExt(url) {
    try {
      var path = new URL(url, window.location.href).pathname.toLowerCase();
      if (path.endsWith('/')) return '';
      var parts = path.split('.');
      if (parts.length < 2) return '';
      var ext = parts[parts.length - 1];
      if (ext.length > 5 || ext.includes('/')) return '';
      return ext;
    } catch(e) { return ''; }
  }

  function isDownload(url) {
    var ext = getExt(url);
    return EXTS.indexOf(ext) !== -1;
  }

  function intercept(url) {
    try {
      var abs = new URL(url, window.location.href).href;
      if (isDownload(abs)) {
        window.ReactNativeWebView.postMessage(JSON.stringify({
          type: 'DOWNLOAD_INTERCEPTED',
          url: abs,
        }));
        return true; // تم الاعتراض
      }
    } catch(e) {}
    return false;
  }

  // اعتراض الضغط على الروابط
  document.addEventListener('click', function(e) {
    var el = e.target;
    // ارتقي لأعلى العناصر لو الضغط كان على عنصر جوه الـ <a>
    while (el && el.tagName !== 'A') el = el.parentElement;
    if (el && el.href && intercept(el.href)) {
      e.preventDefault();
      e.stopImmediatePropagation();
    }
  }, true);

  // اعتراض أي تغيير في window.location نحو ملف
  var _open = window.open;
  window.open = function(url) {
    if (url && intercept(url)) return null;
    return _open.apply(this, arguments);
  };

  true;
})();
`;

// ── Cache ─────────────────────────────────────────────
const safeCache    = new Set<string>(['google.com','gstatic.com','googleapis.com','google.com.eg','ggpht.com','googleusercontent.com','youtube.com','ytimg.com','googlevideo.com']);
const blockedCache = new Set<string>();
const approvedOnce = new Set<string>();

function getHostname(url: string): string {
  try { return new URL(url).hostname.replace(/^www\./, '').toLowerCase(); }
  catch { return ''; }
}

function getFilename(url: string): string {
  try {
    const parts = new URL(url).pathname.split('/');
    return decodeURIComponent(parts[parts.length - 1] || 'unknown');
  } catch { return 'unknown'; }
}

function isDownloadUrl(url: string): boolean {
  try {
    const path = new URL(url).pathname.toLowerCase();
    if (path.endsWith('/')) return false;
    const webPages = ['/wiki/', '/article/', '/page/', '/post/', '/news/', '/blog/'];
    if (webPages.some(p => path.includes(p))) return false;
    const parts = path.split('.');
    if (parts.length < 2) return false;
    const ext = parts.pop() || '';
    if (ext.length > 5 || ext.includes('/')) return false;
    return DOWNLOAD_EXTENSIONS.includes(ext);
  } catch { return false; }
}

async function checkDomain(host: string): Promise<{ allowed: boolean; reason?: string }> {
  if (safeCache.has(host))    return { allowed: true };
  if (blockedCache.has(host)) return { allowed: false, reason: 'موقع محظور' };
  try {
    const res  = await fetch(`${BACKEND_URL}/check-safety`, {
      method: 'POST', headers: HEADERS,
      body: JSON.stringify({ domain: host }),
    });
    const data = await res.json();
    if (data.allowed) safeCache.add(host);
    else              blockedCache.add(host);
    return data;
  } catch {
    return { allowed: false, reason: 'تعذر الاتصال بخادم الفحص' };
  }
}

async function scanFile(fileUrl: string, filename: string): Promise<{ allowed: boolean; reason?: string }> {
  try {
    const res  = await fetch(`${BACKEND_URL}/scan-file`, {
      method: 'POST', headers: HEADERS,
      body: JSON.stringify({ url: fileUrl, filename }),
    });
    return await res.json();
  } catch {
    return { allowed: false, reason: 'تعذر فحص الملف' };
  }
}

function buildUrl(input: string): string {
  const t = input.trim();
  if (!t) return HOME_URL;
  if (t.startsWith('http://') || t.startsWith('https://')) return t;
  if (t.includes('.')) return `https://${t}`;
  return `https://www.google.com/search?q=${encodeURIComponent(t)}`;
}

type Status = 'idle' | 'checking_domain' | 'scanning_file' | 'blocked' | 'file_blocked';

export default function SafeBrowser() {
  const [urlBar,     setUrlBar]     = useState(HOME_URL);
  const [currentUrl, setCurrentUrl] = useState(HOME_URL);
  const [status,     setStatus]     = useState<Status>('idle');
  const [blockMsg,   setBlockMsg]   = useState('');
  const [scanModal,  setScanModal]  = useState(false);
  const [scanFile_,  setScanFile_]  = useState('');
  const webViewRef  = useRef<WebView>(null);
  const pendingUrls = useRef<Set<string>>(new Set());

  const showBlock = useCallback((reason: string, isFile = false) => {
    setBlockMsg(reason);
    setStatus(isFile ? 'file_blocked' : 'blocked');
  }, []);

  // ── بدء مراقبة مجلد Downloads أوتوماتيك ─────────────
  useEffect(() => {
    FileMonitor?.startWatching(SECRET_KEY, BACKEND_URL);

    // استقبال إشعار لو ملف اتحذف لأنه خطير
    const emitter = new NativeEventEmitter(FileMonitor);
    const sub = emitter.addListener('onFileDangerous', (data) => {
      Alert.alert(
        '⚠️ تم حذف ملف خطير!',
        `"${data.name}" تم حذفه تلقائياً\nالسبب: ${data.reason}`,
        [{ text: 'حسناً' }]
      );
    });

    return () => {
      sub.remove();
      FileMonitor?.stopWatching();
    };
  }, []);

  // ── معالجة التحميل المعترض من JS ─────────────────────
  const handleFileDownload = useCallback(async (fileUrl: string) => {
    const filename = getFilename(fileUrl);
    console.log('[DOWNLOAD] Intercepted:', filename);

    setScanFile_(filename);
    setScanModal(true);
    setStatus('scanning_file');

    try {
      // نستخدم الـ Native Module يحمّل ويفحص ويحفظ
      const result = await FileMonitor.downloadAndScan(
        fileUrl, filename, SECRET_KEY, BACKEND_URL
      );

      setScanModal(false);
      setStatus('idle');

      if (result.allowed) {
        Alert.alert('✅ تم التحميل', `"${filename}" نظيف وتم حفظه`);
      } else {
        showBlock(result.reason || 'الملف خطير - لم يُحفظ', true);
      }
    } catch (e) {
      setScanModal(false);
      setStatus('idle');
      showBlock('تعذر فحص الملف', true);
    }
  }, [showBlock]);

  // ── استقبال رسائل JS ──────────────────────────────────
  const onMessage = useCallback((event: WebViewMessageEvent) => {
    try {
      const msg = JSON.parse(event.nativeEvent.data);
      if (msg.type === 'DOWNLOAD_INTERCEPTED' && msg.url) {
        handleFileDownload(msg.url);
      }
    } catch {}
  }, [handleFileDownload]);

  // ── التنقل من شريط العنوان ────────────────────────────
  const navigateTo = useCallback(async (rawInput: string) => {
    const url  = buildUrl(rawInput);
    const host = getHostname(url);

    if (!host || url.includes('google.com/search')) {
      setStatus('idle');
      setCurrentUrl(url);
      return;
    }

    setStatus('checking_domain');
    const result = await checkDomain(host);
    if (result.allowed) {
      setStatus('idle');
      setCurrentUrl(url);
    } else {
      showBlock(result.reason || 'محتوى غير مناسب');
    }
  }, [showBlock]);

  // ── onShouldStart: خط دفاع ثاني (بعد JS) ────────────
  const onShouldStart = useCallback((request: any): boolean => {
    const url: string = request.url;

    if (!url || !url.startsWith('http'))  return true;
    if (request.isTopFrame === false)      return true;

    const host = getHostname(url);
    if (!host) return true;

    // لو ملف تحميل - امنعه دايماً، الـ Native Module هيتولى الأمر
    if (isDownloadUrl(url)) {
      handleFileDownload(url);
      return false;
    }

    // فحص الدومين للصفحات العادية
    if (safeCache.has(host))  return true;
    if (blockedCache.has(host)) {
      setTimeout(() => showBlock('موقع محظور'), 0);
      return false;
    }

    if (pendingUrls.current.has(url)) return false;
    pendingUrls.current.add(url);
    setStatus('checking_domain');

    checkDomain(host).then((result) => {
      pendingUrls.current.delete(url);
      if (result.allowed) {
        setStatus('idle');
        webViewRef.current?.injectJavaScript(
          `window.location.href = ${JSON.stringify(url)}; true;`
        );
      } else {
        showBlock(result.reason || 'محتوى غير مناسب');
      }
    });

    return false;
  }, [showBlock, handleFileDownload]);

  const goHome = useCallback(() => {
    setStatus('idle');
    setBlockMsg('');
    pendingUrls.current.clear();
    approvedOnce.clear();
    setCurrentUrl(HOME_URL);
    setUrlBar(HOME_URL);
  }, []);

  const isBlocked = status === 'blocked' || status === 'file_blocked';

  return (
    <View style={s.container}>

      {/* شريط العنوان */}
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

      {/* Modal فحص الملف */}
      <Modal transparent visible={scanModal} animationType="fade">
        <View style={s.modalBg}>
          <View style={s.modalBox}>
            <Text style={s.modalIcon}>🔍</Text>
            <Text style={s.modalTitle}>جاري فحص الملف</Text>
            <Text style={s.modalFile}>{scanFile_}</Text>
            <ActivityIndicator size="large" color="#007AFF" style={{ marginTop: 16 }} />
            <Text style={s.modalSub}>يتم فحص المحتوى الكامل للملف{'\n'}قبل السماح بالتحميل</Text>
          </View>
        </View>
      </Modal>

      {/* Overlay فحص الدومين */}
      {status === 'checking_domain' && (
        <View style={s.overlay}>
          <ActivityIndicator size="large" color="#007AFF" />
          <Text style={s.checkTxt}>🔍 جاري فحص الأمان...</Text>
        </View>
      )}

      {/* شاشة الحجب أو المتصفح */}
      {isBlocked ? (
        <View style={s.blockScreen}>
          <Text style={s.blockIcon}>{status === 'file_blocked' ? '☣️' : '🚫'}</Text>
          <Text style={s.blockTitle}>
            {status === 'file_blocked' ? 'تحميل الملف محظور!' : 'الموقع محظور!'}
          </Text>
          <Text style={s.blockReason}>{blockMsg}</Text>
          <TouchableOpacity onPress={goHome} style={s.homeBtn}>
            <Text style={s.homeTxt}>العودة للرئيسية</Text>
          </TouchableOpacity>
        </View>
      ) : (
        <WebView
          ref={webViewRef}
          source={{ uri: currentUrl }}
          style={s.webview}
          // JS يُحقن قبل تحميل الصفحة لاعتراض روابط التحميل
          injectedJavaScriptBeforeContentLoaded={INTERCEPT_JS}
          onMessage={onMessage}
          onShouldStartLoadWithRequest={onShouldStart}
          onNavigationStateChange={(nav) => { if (nav.url) setUrlBar(nav.url); }}
          onFileDownload={({ nativeEvent }) => {
            // Android fallback لو JS injection مش اشتغل
            handleFileDownload(nativeEvent.downloadUrl);
          }}
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
  bar: {
    flexDirection: 'row', alignItems: 'center',
    paddingHorizontal: 8, paddingVertical: 10,
    backgroundColor: '#f5f5f5',
    borderBottomWidth: 1, borderBottomColor: '#ddd',
  },
  navBtn: { paddingHorizontal: 12, paddingVertical: 6 },
  navTxt: { fontSize: 32, color: '#007AFF' },
  input: {
    flex: 1, height: 46, backgroundColor: '#fff',
    borderRadius: 12, paddingHorizontal: 14, fontSize: 15,
    borderWidth: 1, borderColor: '#ddd', marginHorizontal: 6,
  },
  overlay: {
    position: 'absolute', top: 0, left: 0, right: 0, bottom: 0,
    justifyContent: 'center', alignItems: 'center',
    backgroundColor: 'rgba(255,255,255,0.95)', zIndex: 10,
  },
  checkTxt: { marginTop: 14, fontSize: 15, color: '#333' },
  webview: { flex: 1 },
  modalBg: {
    flex: 1, justifyContent: 'center', alignItems: 'center',
    backgroundColor: 'rgba(0,0,0,0.5)',
  },
  modalBox: {
    backgroundColor: '#fff', borderRadius: 20, padding: 30,
    alignItems: 'center', width: '80%', elevation: 10,
  },
  modalIcon:  { fontSize: 50, marginBottom: 10 },
  modalTitle: { fontSize: 20, fontWeight: 'bold', color: '#333' },
  modalFile:  { fontSize: 13, color: '#888', marginTop: 6, textAlign: 'center' },
  modalSub:   { fontSize: 13, color: '#999', marginTop: 16, textAlign: 'center', lineHeight: 20 },
  blockScreen: {
    flex: 1, justifyContent: 'center', alignItems: 'center',
    backgroundColor: '#fff5f5', padding: 30,
  },
  blockIcon:   { fontSize: 72, marginBottom: 16 },
  blockTitle:  { fontSize: 26, fontWeight: 'bold', color: '#d00', marginBottom: 10 },
  blockReason: { fontSize: 15, color: '#555', textAlign: 'center', marginBottom: 30, lineHeight: 24 },
  homeBtn: {
    backgroundColor: '#4CAF50', paddingVertical: 12,
    paddingHorizontal: 32, borderRadius: 24,
  },
  homeTxt: { color: '#fff', fontSize: 16, fontWeight: 'bold' },
});