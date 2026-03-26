package com.dnsprotectorapp

import android.os.Environment
import android.os.FileObserver
import android.util.Base64
import com.facebook.react.bridge.*
import com.facebook.react.modules.core.DeviceEventManagerModule
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL

class FileMonitorModule(private val reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    override fun getName() = "FileMonitor"

    private val downloadsDir: File =
        Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)

    private val blockedFiles = mutableSetOf<String>()
    private val scannedSafe  = mutableSetOf<String>()

    private var fileObserver: FileObserver? = null
    private var currentApiKey   = ""
    private var currentBackend  = ""

    // ════════════════════════════════════════════════════
    // downloadAndScan
    // بيحمّل الملف على السيرفر، يفحصه، ولو نظيف يحفظه
    // ده البديل الكامل لـ Android Download Manager
    // ════════════════════════════════════════════════════
    @ReactMethod
    fun downloadAndScan(fileUrl: String, filename: String, apiKey: String, backendUrl: String, promise: Promise) {
        Thread {
            try {
                println("\n📥 downloadAndScan: $filename")

                // ── 1. أرسل للسيرفر عشان يفحص ────────────
                val scanUrl  = URL("$backendUrl/scan-file")
                val scanConn = scanUrl.openConnection() as HttpURLConnection
                scanConn.requestMethod = "POST"
                scanConn.setRequestProperty("Content-Type", "application/json")
                scanConn.setRequestProperty("X-API-KEY", apiKey)
                scanConn.doOutput      = true
                scanConn.connectTimeout = 15000
                scanConn.readTimeout    = 60000

                val body = """{"url":"$fileUrl","filename":"$filename"}"""
                scanConn.outputStream.write(body.toByteArray())

                val scanResponse = scanConn.inputStream.bufferedReader().readText()
                scanConn.disconnect()

                val allowed = scanResponse.contains("\"allowed\":true")
                val reason  = Regex("\"reason\":\"([^\"]+)\"")
                    .find(scanResponse)?.groupValues?.get(1) ?: ""

                if (!allowed) {
                    // ── ممنوع - لا يُحفظ على الجهاز ─────
                    println("⛔ Blocked: $filename | $reason")
                    val result = WritableNativeMap()
                    result.putBoolean("allowed", false)
                    result.putString("reason",   reason)
                    promise.resolve(result)
                    return@Thread
                }

                // ── 2. نظيف - حمّله وحفظه في Downloads ──
                println("✅ Safe - downloading: $filename")
                val destFile = File(downloadsDir, filename)

                val dlUrl  = URL(fileUrl)
                val dlConn = dlUrl.openConnection() as HttpURLConnection
                dlConn.setRequestProperty("User-Agent", "Mozilla/5.0")
                dlConn.connectTimeout = 15000
                dlConn.readTimeout    = 120000

                val input  = dlConn.inputStream
                val output = FileOutputStream(destFile)
                val buffer = ByteArray(8192)
                var bytesRead: Int

                while (input.read(buffer).also { bytesRead = it } != -1) {
                    output.write(buffer, 0, bytesRead)
                }

                output.flush()
                output.close()
                input.close()
                dlConn.disconnect()

                scannedSafe.add(destFile.absolutePath)
                println("💾 Saved: ${destFile.absolutePath}")

                // أرسل إشعار للـ React Native إن الملف اتحمل
                sendEvent("onFileDownloaded", mapOf(
                    "name"    to filename,
                    "path"    to destFile.absolutePath,
                    "allowed" to true
                ))

                val result = WritableNativeMap()
                result.putBoolean("allowed", true)
                result.putString("path",     destFile.absolutePath)
                result.putString("reason",   "نظيف - تم الحفظ")
                promise.resolve(result)

            } catch (e: Exception) {
                println("❌ Error: ${e.message}")
                promise.reject("DOWNLOAD_ERROR", e.message)
            }
        }.start()
    }

    // ════════════════════════════════════════════════════
    // startWatching - مراقبة مجلد Downloads أوتوماتيك
    // لو أي ملف اتحمل من أي مكان يتفحص فوراً
    // ════════════════════════════════════════════════════
    @ReactMethod
    fun startWatching(apiKey: String, backendUrl: String) {
        currentApiKey  = apiKey
        currentBackend = backendUrl

        fileObserver?.stopWatching()
        fileObserver = object : FileObserver(downloadsDir.absolutePath, CLOSE_WRITE) {
            override fun onEvent(event: Int, path: String?) {
                if (path == null) return
                val file = File(downloadsDir, path)
                if (!file.isFile) return
                if (scannedSafe.contains(file.absolutePath))  return
                if (blockedFiles.contains(file.absolutePath)) return

                println("👁️ New file detected: $path")
                autoScanFile(file)
            }
        }
        fileObserver?.startWatching()
        println("👁️ Watching Downloads folder...")
    }

    @ReactMethod
    fun stopWatching() {
        fileObserver?.stopWatching()
        fileObserver = null
    }

    // ════════════════════════════════════════════════════
    // autoScanFile - يفحص ملف موجود في الجهاز ويحذفه لو خطير
    // ════════════════════════════════════════════════════
    private fun autoScanFile(file: File) {
        Thread {
            try {
                val maxBytes   = 1 * 1024 * 1024
                val bytes      = file.inputStream().use { s ->
                    val buf  = ByteArray(maxBytes)
                    val read = s.read(buf)
                    if (read > 0) buf.copyOf(read) else byteArrayOf()
                }

                val base64 = Base64.encodeToString(bytes, Base64.NO_WRAP)

                val url  = URL("$currentBackend/scan-local-file")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Content-Type", "application/json")
                conn.setRequestProperty("X-API-KEY", currentApiKey)
                conn.doOutput       = true
                conn.connectTimeout = 15000
                conn.readTimeout    = 30000

                val body = """{"filename":"${file.name}","content":"$base64","size":${file.length()}}"""
                conn.outputStream.write(body.toByteArray())

                val response = conn.inputStream.bufferedReader().readText()
                conn.disconnect()

                val allowed = response.contains("\"allowed\":true")
                val reason  = Regex("\"reason\":\"([^\"]+)\"")
                    .find(response)?.groupValues?.get(1) ?: ""

                if (!allowed) {
                    println("⛔ Auto-blocked & deleted: ${file.name}")
                    file.delete()
                    blockedFiles.add(file.absolutePath)
                    sendEvent("onFileDangerous", mapOf(
                        "name"   to file.name,
                        "reason" to reason
                    ))
                } else {
                    scannedSafe.add(file.absolutePath)
                    sendEvent("onFileScanned", mapOf(
                        "name"    to file.name,
                        "allowed" to true
                    ))
                }

            } catch (e: Exception) {
                println("❌ AutoScan error: ${e.message}")
            }
        }.start()
    }

    // ════════════════════════════════════════════════════
    // getDownloadsList / deleteFile / scanDownloadsFolder
    // ════════════════════════════════════════════════════
    @ReactMethod
    fun getDownloadsList(promise: Promise) {
        try {
            val list  = WritableNativeArray()
            val files = (downloadsDir.listFiles() ?: emptyArray())
                .filter { it.isFile }
                .sortedByDescending { it.lastModified() }

            for (file in files) {
                val item = WritableNativeMap()
                item.putString("name",     file.name)
                item.putString("path",     file.absolutePath)
                item.putDouble("size",     file.length().toDouble())
                item.putDouble("modified", file.lastModified().toDouble())
                item.putBoolean("blocked", blockedFiles.contains(file.absolutePath))
                item.putBoolean("safe",    scannedSafe.contains(file.absolutePath))
                list.pushMap(item)
            }
            promise.resolve(list)
        } catch (e: Exception) {
            promise.reject("LIST_ERROR", e.message)
        }
    }

    @ReactMethod
    fun deleteFile(filePath: String, promise: Promise) {
        try {
            val file = File(filePath)
            if (file.exists() && file.absolutePath.startsWith(downloadsDir.absolutePath)) {
                file.delete()
                blockedFiles.remove(filePath)
                scannedSafe.remove(filePath)
                promise.resolve(true)
            } else {
                promise.resolve(false)
            }
        } catch (e: Exception) {
            promise.reject("DELETE_ERROR", e.message)
        }
    }

    @ReactMethod
    fun scanDownloadsFolder(apiKey: String, backendUrl: String, promise: Promise) {
        Thread {
            try {
                val results = WritableNativeArray()
                val files   = (downloadsDir.listFiles() ?: emptyArray()).filter { it.isFile }

                for (file in files) {
                    val result = WritableNativeMap()
                    result.putString("name", file.name)
                    result.putString("path", file.absolutePath)
                    result.putDouble("size", file.length().toDouble())

                    if (scannedSafe.contains(file.absolutePath)) {
                        result.putBoolean("allowed", true)
                        result.putString("reason",  "سبق فحصه - نظيف")
                        results.pushMap(result)
                        continue
                    }

                    val maxBytes = 1 * 1024 * 1024
                    val bytes    = file.inputStream().use { s ->
                        val buf  = ByteArray(maxBytes)
                        val read = s.read(buf)
                        if (read > 0) buf.copyOf(read) else byteArrayOf()
                    }
                    val base64 = Base64.encodeToString(bytes, Base64.NO_WRAP)

                    val url  = URL("$backendUrl/scan-local-file")
                    val conn = url.openConnection() as HttpURLConnection
                    conn.requestMethod = "POST"
                    conn.setRequestProperty("Content-Type", "application/json")
                    conn.setRequestProperty("X-API-KEY", apiKey)
                    conn.doOutput = true
                    val body = """{"filename":"${file.name}","content":"$base64","size":${file.length()}}"""
                    conn.outputStream.write(body.toByteArray())
                    val response = conn.inputStream.bufferedReader().readText()
                    conn.disconnect()

                    val allowed = response.contains("\"allowed\":true")
                    val reason  = Regex("\"reason\":\"([^\"]+)\"")
                        .find(response)?.groupValues?.get(1) ?: ""

                    result.putBoolean("allowed", allowed)
                    result.putString("reason",  reason)

                    if (allowed) scannedSafe.add(file.absolutePath)
                    else { blockedFiles.add(file.absolutePath); file.delete() }

                    results.pushMap(result)
                }

                promise.resolve(results)
            } catch (e: Exception) {
                promise.reject("SCAN_ERROR", e.message)
            }
        }.start()
    }

    // ── إرسال Events لـ React Native ──────────────────
    private fun sendEvent(eventName: String, data: Map<String, Any>) {
        try {
            val params = WritableNativeMap()
            for ((k, v) in data) when (v) {
                is String  -> params.putString(k, v)
                is Boolean -> params.putBoolean(k, v)
                is Int     -> params.putInt(k, v)
            }
            reactContext
                .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java)
                .emit(eventName, params)
        } catch (e: Exception) {
            println("sendEvent error: ${e.message}")
        }
    }

    @ReactMethod
    fun addListener(eventName: String) {}

    @ReactMethod
    fun removeListeners(count: Int) {}
}