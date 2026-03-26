import React, { useEffect, useState, useCallback } from 'react';
import {
  View, Text, FlatList, StyleSheet, TouchableOpacity,
  ActivityIndicator, Alert, NativeModules, RefreshControl,
  PermissionsAndroid, Platform, NativeEventEmitter,
} from 'react-native';

const { FileMonitor } = NativeModules;

// ── التحقق من وجود الـ Native Module ─────────────────
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

function formatSize(bytes: number): string {
  if (bytes < 1024)          return `${bytes} B`;
  if (bytes < 1024 * 1024)   return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export default function DownloadScanner() {
  const [files,     setFiles]     = useState<FileItem[]>([]);
  const [scanning,  setScanning]  = useState(false);
  const [loading,   setLoading]   = useState(true);
  const [scanStats, setScanStats] = useState({ total: 0, blocked: 0, safe: 0 });

  // ── تحميل قائمة الملفات ─────────────────────────────
  const requestPermission = useCallback(async (): Promise<boolean> => {
    if (Platform.OS !== 'android') return true;
    try {
      // Android 13+
      if (Platform.Version >= 33) return true;

      const granted = await PermissionsAndroid.request(
        PermissionsAndroid.PERMISSIONS.READ_EXTERNAL_STORAGE,
        {
          title:   'إذن الوصول للملفات',
          message: 'التطبيق يحتاج إذن لفحص مجلد التحميل',
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
      setScanStats({
        total:   list.length,
        blocked: list.filter(f => f.blocked).length,
        safe:    list.filter(f => f.safe).length,
      });
    } catch (e) {
      Alert.alert('خطأ', 'Load files error: ' + String(e));
    }
    setLoading(false);
  }, [requestPermission]);

  // ── فحص كل الملفات ───────────────────────────────────
  const scanAll = useCallback(async () => {
    setScanning(true);
    try {
      const results: FileItem[] = await FileMonitor.scanDownloadsFolder(
        SECRET_KEY,
        BACKEND_URL,
      );

      // دمج النتائج مع القائمة الحالية
      setFiles(prev => prev.map(f => {
        const scanned = results.find(r => r.path === f.path);
        return scanned ? { ...f, ...scanned } : f;
      }));

      const blocked = results.filter(r => !r.allowed).length;
      const safe    = results.filter(r =>  r.allowed).length;

      setScanStats({ total: results.length, blocked, safe });

      if (blocked > 0) {
        Alert.alert(
          '⚠️ تحذير!',
          `تم اكتشاف ${blocked} ملف خطير في مجلد التحميل!\nيرجى حذفها فوراً.`,
          [{ text: 'حسناً', style: 'default' }]
        );
      } else {
        Alert.alert('✅ نظيف', `تم فحص ${safe} ملف - كلها آمنة`);
      }

    } catch (e) {
      Alert.alert('خطأ', 'فشل الفحص: ' + String(e));
    }
    setScanning(false);
    loadFiles();
  }, [loadFiles]);

  // ── حذف ملف ──────────────────────────────────────────
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
    loadFiles().then(() => {
      // فحص أوتوماتيك عند الفتح لو فيه ملفات لم تُفحص
      scanAll();
    });

    // استقبال إشعارات الملفات الجديدة من FileObserver
    if (isModuleAvailable) {
      const emitter = new NativeEventEmitter(FileMonitor);
      const s1 = emitter.addListener('onFileDangerous', () => loadFiles());
      const s2 = emitter.addListener('onFileScanned',   () => loadFiles());
      const s3 = emitter.addListener('onFileDownloaded',() => loadFiles());
      return () => { s1.remove(); s2.remove(); s3.remove(); };
    }
  }, []);

  // ── عرض كل ملف ───────────────────────────────────────
  const renderFile = ({ item }: { item: FileItem }) => {
    const isBlocked = item.blocked;
    const isSafe    = item.safe;
    const isPending = !isBlocked && !isSafe;

    return (
      <View style={[s.fileCard, isBlocked && s.fileCardBlocked]}>
        <View style={s.fileIcon}>
          <Text style={s.fileIconTxt}>
            {isBlocked ? '☣️' : isSafe ? '✅' : '📄'}
          </Text>
        </View>

        <View style={s.fileInfo}>
          <Text style={[s.fileName, isBlocked && s.fileNameBlocked]} numberOfLines={1}>
            {item.name}
          </Text>
          <Text style={s.fileMeta}>{formatSize(item.size)}</Text>
          {isBlocked && (
            <Text style={s.fileReason} numberOfLines={2}>{item.reason}</Text>
          )}
          {isPending && (
            <Text style={s.filePending}>لم يتم الفحص بعد</Text>
          )}
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
      {/* Header */}
      <View style={s.header}>
        <Text style={s.title}>🛡️ فاحص التحميلات</Text>
        <Text style={s.subtitle}>مجلد Downloads</Text>
      </View>

      {/* Stats */}
      <View style={s.stats}>
        <View style={[s.stat, { backgroundColor: '#e8f5e9' }]}>
          <Text style={s.statNum}>{scanStats.safe}</Text>
          <Text style={s.statLbl}>آمن</Text>
        </View>
        <View style={[s.stat, { backgroundColor: '#fff3e0' }]}>
          <Text style={s.statNum}>{scanStats.total}</Text>
          <Text style={s.statLbl}>إجمالي</Text>
        </View>
        <View style={[s.stat, { backgroundColor: '#ffebee' }]}>
          <Text style={s.statNum}>{scanStats.blocked}</Text>
          <Text style={s.statLbl}>خطير</Text>
        </View>
      </View>

      {/* مؤشر الفحص التلقائي */}
      {scanning && (
        <View style={s.autoScan}>
          <ActivityIndicator size="small" color="#007AFF" />
          <Text style={s.autoScanTxt}>  جاري الفحص التلقائي...</Text>
        </View>
      )}

      {/* قائمة الملفات */}
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
  container:  { flex: 1, backgroundColor: '#f8f9fa' },
  header:     { backgroundColor: '#1a1a2e', padding: 20, paddingTop: 40, alignItems: 'center' },
  title:      { fontSize: 22, fontWeight: 'bold', color: '#fff' },
  subtitle:   { fontSize: 13, color: '#aaa', marginTop: 4 },

  stats: { flexDirection: 'row', margin: 12, gap: 8 },
  stat:  { flex: 1, borderRadius: 12, padding: 12, alignItems: 'center' },
  statNum: { fontSize: 24, fontWeight: 'bold', color: '#333' },
  statLbl: { fontSize: 12, color: '#666', marginTop: 2 },

  autoScan: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'center',
    paddingVertical: 8, marginBottom: 4,
  },
  autoScanTxt: { color: '#007AFF', fontSize: 13 },

  fileCard: {
    flexDirection: 'row', alignItems: 'center',
    backgroundColor: '#fff', marginHorizontal: 12,
    marginTop: 8, borderRadius: 12, padding: 12, elevation: 2,
  },
  fileCardBlocked: { backgroundColor: '#fff5f5', borderWidth: 1, borderColor: '#ffcdd2' },
  fileIcon:        { width: 44, alignItems: 'center' },
  fileIconTxt:     { fontSize: 28 },
  fileInfo:        { flex: 1, marginLeft: 8 },
  fileName:        { fontSize: 14, fontWeight: '600', color: '#222' },
  fileNameBlocked: { color: '#c62828' },
  fileMeta:        { fontSize: 12, color: '#888', marginTop: 2 },
  fileReason:      { fontSize: 11, color: '#e53935', marginTop: 3 },
  filePending:     { fontSize: 11, color: '#fb8c00', marginTop: 3 },

  deleteBtn: { padding: 8 },
  deleteTxt: { fontSize: 22 },

  empty:    { flex: 1, alignItems: 'center', justifyContent: 'center' },
  emptyIcon: { fontSize: 60, marginBottom: 12 },
  emptyTxt:  { fontSize: 16, color: '#888' },
});