import React, { useState } from 'react';
import { View, Text, TouchableOpacity, StyleSheet } from 'react-native';
import SafeBrowser     from './SafeBrowser';
import DownloadScanner from './DownloadScanner';

type Screen = 'home' | 'browser' | 'scanner';

export default function App() {
  const [screen, setScreen] = useState<Screen>('home');

  if (screen === 'home') {
    return (
      <View style={s.home}>
        <Text style={s.homeIcon}>🛡️</Text>
        <Text style={s.homeTitle}>المتصفح الآمن</Text>
        <Text style={s.homeSub}>تصفح آمن ومحمي لأطفالك</Text>
        <TouchableOpacity style={s.homeBtn} onPress={() => setScreen('browser')}>
          <Text style={s.homeBtnTxt}>🌐  ابدأ التصفح</Text>
        </TouchableOpacity>
        <TouchableOpacity style={[s.homeBtn, s.scannerBtn]} onPress={() => setScreen('scanner')}>
          <Text style={s.homeBtnTxt}>🔍   مجلد التحميل</Text>
        </TouchableOpacity>
      </View>
    );
  }

  return (
    <View style={{ flex: 1 }}>
      {screen === 'browser' && <SafeBrowser />}
      {screen === 'scanner' && <DownloadScanner />}
      <View style={s.tabBar}>
        <TouchableOpacity
          style={[s.tab, screen === 'browser' && s.tabActive]}
          onPress={() => setScreen('browser')}
        >
          <Text style={s.tabIcon}>🌐</Text>
          <Text style={[s.tabTxt, screen === 'browser' && s.tabTxtActive]}>المتصفح</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[s.tab, screen === 'scanner' && s.tabActive]}
          onPress={() => setScreen('scanner')}
        >
          <Text style={s.tabIcon}>🔍</Text>
          <Text style={[s.tabTxt, screen === 'scanner' && s.tabTxtActive]}>التحميلات</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
}

const s = StyleSheet.create({
  home:      { flex: 1, justifyContent: 'center', alignItems: 'center', backgroundColor: '#f0f4ff', padding: 30 },
  homeIcon:  { fontSize: 80, marginBottom: 20 },
  homeTitle: { fontSize: 28, fontWeight: 'bold', color: '#1a1a2e', marginBottom: 10 },
  homeSub:   { fontSize: 16, color: '#555', marginBottom: 50, textAlign: 'center' },
  homeBtn:   { backgroundColor: '#007AFF', width: '100%', paddingVertical: 16, borderRadius: 30, alignItems: 'center', marginBottom: 14, elevation: 4 },
  scannerBtn:   { backgroundColor: '#4CAF50' },
  homeBtnTxt:   { color: '#fff', fontSize: 18, fontWeight: 'bold' },
  tabBar:       { flexDirection: 'row', backgroundColor: '#fff', borderTopWidth: 1, borderTopColor: '#ddd', paddingBottom: 8 },
  tab:          { flex: 1, alignItems: 'center', paddingVertical: 8 },
  tabActive:    { borderTopWidth: 2, borderTopColor: '#007AFF' },
  tabIcon:      { fontSize: 20 },
  tabTxt:       { fontSize: 11, color: '#999', marginTop: 2 },
  tabTxtActive: { color: '#007AFF', fontWeight: 'bold' },
});