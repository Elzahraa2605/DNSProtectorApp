import React, { useEffect, useState, useCallback } from 'react';
import {
  View, Text, FlatList, StyleSheet, TouchableOpacity,
  ActivityIndicator, Alert, NativeModules, RefreshControl,
  PermissionsAndroid, Platform, NativeEventEmitter, Animated,
} from 'react-native';

const { FileMonitor } = NativeModules;
const isModuleAvailable = !!FileMonitor;

const BACKEND_URL = 'http://10.0.2.2:9000';
const SECRET_KEY  = 'zahraa-secret-2026';

type FileItem = {
  name:     string;
  path:     string;
  size:     number;
  modified: number;
  blocked:  boolean;
  safe:     boolean;
  allowed?: boolean;
  reason?:  string;
};

type ScanProgress = {
  current:  number;
  total:    number;
  filename: string;
};

function formatSize(bytes: number): string {
  if (bytes < 1024)          return `${bytes} B`;
  if (bytes < 1024 * 1024)   return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function formatDate(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleDateString('ar-EG', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
}

export default function DownloadScanner() {
  const [files,     setFiles]     = useState<FileItem[]>([]);
  const [scanning,  setScanning]  = useState(false);
  const [loading,   setLoading]   = useState(true);
  const [progress,  setProgress]  = useState<ScanProgress | null>(null);
  const [scanStats, setScanStats] = useState({ total: 0, blocked: 0, safe: 0, pending: 0 });

  const requestPermission = useCallback(async (): Promise<boolean> => {
    if (Platform.OS !== 'android') return true;
    try {
      if (Platform.Version >= 33) return true;
      const granted = await PermissionsAndroid.request(
        PermissionsAndroid.PERMISSIONS.READ_EXTERNAL_STORAGE,
        {
          title:          'إذن الوصول للملفات',
          message:        'التطبيق يحتاج إذن لفحص مجلد التحميل',
          buttonPositive: 'السماح',
          buttonNegative: 'رفض',
        }
      );
      return granted === PermissionsAndroid.RESULTS.GRANTED;
    } catch { return false; }
  }, []);

  const loadFiles = useCallback(async () => {
    if (!isModuleAvailable) {
      setLoading(false);
      Alert.alert('تنبيه', 'يجب إضافة FileMonitorPackage في MainApplication.kt أولاً');
      return;
    }

    const hasPermission = await requestPermission();
    if (!hasPermission) {
      setLoading(false);
      Alert.alert('تنبيه', 'تم رفض إذن الوصول للملفات');
      return;
    }

    setLoading(true);
    try {
      const list: FileItem[] = await FileMonitor.getDownloadsList();
      setFiles(list);
      updateStats(list);
    } catch (e) {
      Alert.alert('خطأ', 'تعذّر تحميل القائمة: ' + String(e));
    }
    setLoading(false);
  }, [requestPermission]);

  const updateStats = (list: FileItem[]) => {
    setScanStats({
      total:   list.length,
      blocked: list.filter(f => f.blocked).length,
      safe:    list.filter(f => f.safe).length,
      pending: list.filter(f => !f.blocked && !f.safe).length,
    });
  };

  const scanAll = useCallback(async () => {
    if (scanning) return;
    setScanning(true);
    setProgress({ current: 0, total: 0, filename: '...' });

    try {
      const results: FileItem[] = await FileMonitor.scanDownloadsFolder(
        SECRET_KEY,
        BACKEND_URL,
      );

      setFiles(prev => prev.map(f => {
        const scanned = results.find(r => r.path === f.path);
        return scanned ? { ...f, ...scanned } : f;
      }));

      updateStats(results);

      const blocked = results.filter(r => !r.allowed).length;
      const safe    = results.filter(r =>  r.allowed).length;

      if (blocked > 0) {
        Alert.alert(
          '⚠️ تحذير!',
          `تم اكتشاف ${blocked} ملف خطير وحذفه تلقائياً من مجلد التحميل.`,
          [{ text: 'حسناً' }]
        );
      } else {
        Alert.alert('✅ آمن', `تم فحص ${safe} ملف — كلها نظيفة`);
      }

    } catch (e) {
      Alert.alert('خطأ', 'فشل الفحص: ' + String(e));
    }
    setScanning(false);
    setProgress(null);
    loadFiles();
  }, [scanning, loadFiles]);

  const deleteFile = useCallback((file: FileItem) => {
    Alert.alert(
      'حذف الملف',
      `هل تريد حذف "${file.name}"؟`,
      [
        { text: 'إلغاء', style: 'cancel' },
        {
          text: 'حذف', style: 'destructive',
          onPress: async () => {
            await FileMonitor.deleteFile(file.path);
            loadFiles();
          }
        }
      ]
    );
  }, [loadFiles]);

  useEffect(() => {
    loadFiles().then(() => scanAll());

    if (!isModuleAvailable) return;

    const emitter = new NativeEventEmitter(FileMonitor);

    const s1 = emitter.addListener('onFileDangerous', () => loadFiles());
    const s2 = emitter.addListener('onFileScanned',   () => loadFiles());
    const s3 = emitter.addListener('onFileDownloaded',() => loadFiles());
    const s4 = emitter.addListener('onScanProgress', (data: ScanProgress) => {
      setProgress(data);
    });
    const s5 = emitter.addListener('onScanComplete', () => {
      setProgress(null);
      loadFiles();
    });

    return () => { s1.remove(); s2.remove(); s3.remove(); s4.remove(); s5.remove(); };
  }, []);

  const ProgressBar = () => {
    if (!progress || !scanning) return null;
    const pct = progress.total > 0
      ? Math.round((progress.current / progress.total) * 100)
      : 0;

    return (
      <View style={s.progressContainer}>
        <View style={s.progressHeader}>
          <Text style={s.progressTitle}>🔬 جاري الفحص...</Text>
          <Text style={s.progressPct}>{pct}%</Text>
        </View>
        <View style={s.progressBarBg}>
          <View style={[s.progressBarFill, { width: `${pct}%` }]} />
        </View>
        <Text style={s.progressFile} numberOfLines={1}>
          {progress.current}/{progress.total} — {progress.filename}
        </Text>
      </View>
    );
  };

  const renderFile = ({ item }: { item: FileItem }) => {
    const isBlocked = item.blocked;
    const isSafe    = item.safe;
    const isPending = !isBlocked && !isSafe;
    const icon = isBlocked ? '☣️' : isSafe ? '✅' : '📄';
    const ext  = item.name.split('.').pop()?.toUpperCase() ?? '?';

    return (
      <View style={[s.fileCard, isBlocked && s.fileCardBlocked, isSafe && s.fileCardSafe]}>
        <View style={s.fileIconWrap}>
          <Text style={s.fileIconTxt}>{icon}</Text>
          <Text style={s.fileExt}>{ext}</Text>
        </View>

        <View style={s.fileInfo}>
          <Text style={[s.fileName, isBlocked && s.fileNameBlocked]} numberOfLines={1}>
            {item.name}
          </Text>
          <Text style={s.fileMeta}>
            {formatSize(item.size)}
            {item.modified ? ` · ${formatDate(item.modified)}` : ''}
          </Text>
          {isBlocked  && <Text style={s.fileReason}  numberOfLines={2}>⚠️ {item.reason}</Text>}
          {isPending  && <Text style={s.filePending}>⏳ لم يتم الفحص بعد</Text>}
          {isSafe     && <Text style={s.fileSafe}>نظيف ✓</Text>}
        </View>

        {isBlocked && (
          <TouchableOpacity onPress={() => deleteFile(item)} style={s.deleteBtn}>
            <Text style={s.deleteTxt}>🗑️</Text>
          </TouchableOpacity>
        )}
      </View>
    );
  };

  return (
    <View style={s.container}>

      <View style={s.header}>
        <Text style={s.title}>🛡️ فاحص التحميلات</Text>
        <Text style={s.subtitle}>مجلد Downloads — فحص بـ 7 طبقات</Text>
      </View>

      <View style={s.stats}>
        <View style={[s.stat, { backgroundColor: '#e8f5e9' }]}>
          <Text style={[s.statNum, { color: '#2e7d32' }]}>{scanStats.safe}</Text>
          <Text style={s.statLbl}>✅ آمن</Text>
        </View>
        <View style={[s.stat, { backgroundColor: '#fff3e0' }]}>
          <Text style={[s.statNum, { color: '#e65100' }]}>{scanStats.pending}</Text>
          <Text style={s.statLbl}>⏳ معلّق</Text>
        </View>
        <View style={[s.stat, { backgroundColor: '#ffebee' }]}>
          <Text style={[s.statNum, { color: '#b71c1c' }]}>{scanStats.blocked}</Text>
          <Text style={s.statLbl}>☣️ خطير</Text>
        </View>
        <View style={[s.stat, { backgroundColor: '#e3f2fd' }]}>
          <Text style={[s.statNum, { color: '#1565c0' }]}>{scanStats.total}</Text>
          <Text style={s.statLbl}>📂 إجمالي</Text>
        </View>
      </View>

      <TouchableOpacity
        style={[s.scanBtn, scanning && s.scanBtnDisabled]}
        onPress={scanAll}
        disabled={scanning}
      >
        {scanning
          ? <ActivityIndicator size="small" color="#fff" />
          : <Text style={s.scanBtnTxt}>🔬 فحص الكل الآن</Text>
        }
      </TouchableOpacity>

      <ProgressBar />

      {loading ? (
        <ActivityIndicator size="large" color="#007AFF" style={{ marginTop: 40 }} />
      ) : files.length === 0 ? (
        <View style={s.empty}>
          <Text style={s.emptyIcon}>📂</Text>
          <Text style={s.emptyTxt}>مجلد التحميل فاضي</Text>
        </View>
      ) : (
        <FlatList
          data={files}
          keyExtractor={item => item.path}
          renderItem={renderFile}
          refreshControl={
            <RefreshControl refreshing={loading} onRefresh={loadFiles} />
          }
          contentContainerStyle={{ paddingBottom: 20 }}
        />
      )}
    </View>
  );
}

const s = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f0f4f8' },
  header:   { backgroundColor: '#1a1a2e', padding: 20, paddingTop: 40, alignItems: 'center' },
  title:    { fontSize: 22, fontWeight: 'bold', color: '#fff' },
  subtitle: { fontSize: 12, color: '#aaa', marginTop: 4 },
  stats:   { flexDirection: 'row', margin: 12, gap: 8 },
  stat:    { flex: 1, borderRadius: 12, padding: 10, alignItems: 'center', elevation: 1 },
  statNum: { fontSize: 22, fontWeight: 'bold' },
  statLbl: { fontSize: 10, color: '#555', marginTop: 2 },
  scanBtn:         { margin: 12, marginTop: 4, backgroundColor: '#007AFF', borderRadius: 14, paddingVertical: 14, alignItems: 'center', elevation: 3 },
  scanBtnDisabled: { backgroundColor: '#90CAF9' },
  scanBtnTxt:      { color: '#fff', fontSize: 16, fontWeight: 'bold' },
  progressContainer: { marginHorizontal: 12, marginBottom: 8, backgroundColor: '#fff', borderRadius: 12, padding: 12, elevation: 2 },
  progressHeader: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 6 },
  progressTitle:  { fontSize: 13, fontWeight: '600', color: '#333' },
  progressPct:    { fontSize: 13, fontWeight: 'bold', color: '#007AFF' },
  progressBarBg:  { height: 8, backgroundColor: '#e0e0e0', borderRadius: 4, overflow: 'hidden' },
  progressBarFill:{ height: 8, backgroundColor: '#007AFF', borderRadius: 4 },
  progressFile:   { fontSize: 11, color: '#888', marginTop: 6 },
  fileCard: { flexDirection: 'row', alignItems: 'center', backgroundColor: '#fff', marginHorizontal: 12, marginTop: 8, borderRadius: 14, padding: 12, elevation: 2 },
  fileCardBlocked: { backgroundColor: '#fff5f5', borderWidth: 1, borderColor: '#ef9a9a' },
  fileCardSafe:    { borderLeftWidth: 3, borderLeftColor: '#43a047' },
  fileIconWrap: { width: 48, alignItems: 'center' },
  fileIconTxt:  { fontSize: 26 },
  fileExt:      { fontSize: 9, color: '#999', marginTop: 2, fontWeight: '600' },
  fileInfo:        { flex: 1, marginLeft: 8 },
  fileName:        { fontSize: 14, fontWeight: '600', color: '#222' },
  fileNameBlocked: { color: '#c62828' },
  fileMeta:        { fontSize: 11, color: '#888', marginTop: 2 },
  fileReason:      { fontSize: 11, color: '#e53935', marginTop: 4 },
  filePending:     { fontSize: 11, color: '#fb8c00', marginTop: 3 },
  fileSafe:        { fontSize: 11, color: '#43a047', marginTop: 3 },
  deleteBtn: { padding: 8 },
  deleteTxt: { fontSize: 22 },
  empty:    { flex: 1, alignItems: 'center', justifyContent: 'center', marginTop: 80 },
  emptyIcon: { fontSize: 64, marginBottom: 12 },
  emptyTxt:  { fontSize: 16, color: '#888' },
});
// The style definitions and structure are already correctly implemented.