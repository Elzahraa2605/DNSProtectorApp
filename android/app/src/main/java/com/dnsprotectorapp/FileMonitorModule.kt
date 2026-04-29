package com.dnsprotectorapp

import android.content.Context
import android.content.SharedPreferences
import android.os.Environment
import android.os.FileObserver
import android.util.Base64
import com.facebook.react.bridge.*
import com.facebook.react.modules.core.DeviceEventManagerModule
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class FileMonitorModule(private val reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    override fun getName() = "FileMonitor"

    private val downloadsDir: File =
        Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)

    // ── In-memory state ──────────────────────────────────
    private val blockedFiles = mutableSetOf<String>()
    private val scannedSafe  = mutableSetOf<String>()

    // ── Persistent cache (survives app restart) ──────────
    private val prefs: SharedPreferences by lazy {
        reactContext.getSharedPreferences("scan_cache_v2", Context.MODE_PRIVATE)
    }

    private var fileObserver:    FileObserver? = null
    private var currentApiKey  = ""
    private var currentBackend = ""

    // Extensions that are always safe — skip server scan
    private val safeExtensions = setOf(
        "jpg", "jpeg", "png", "gif", "webp", "bmp", "svg", "ico",
        "mp3", "wav", "ogg", "flac", "m4a", "aac",
        "mp4", "mkv", "avi", "mov", "webm", "flv",
        "txt", "md", "csv", "log",
        "ttf", "otf", "woff", "woff2",
    )

    // Extensions that are always dangerous — block immediately
    private val dangerousExtensions = setOf(
        "exe", "dll", "bat", "cmd", "com", "pif", "scr",
        "vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1",
        "msi", "msp", "hta", "reg", "lnk", "inf",
        "jar", "class", "dex",
        "sh", "bash", "zsh",
    )

    // ════════════════════════════════════════════════════
    // Persistent Cache Helpers
    // ════════════════════════════════════════════════════
    private fun computeFileHash(file: File): String {
        // Use MD5 of (filename + size + lastModified) as a fast cache key
        // Avoids reading the whole file just for hashing
        val input = "${file.name}|${file.length()}|${file.lastModified()}"
        val digest = MessageDigest.getInstance("MD5")
        return digest.digest(input.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    private fun isKnownSafe(file: File): Boolean {
        val hash = computeFileHash(file)
        val cached = prefs.getString(hash, null) ?: return false
        return cached == "safe"
    }

    private fun isKnownBlocked(file: File): Boolean {
        val hash = computeFileHash(file)
        val cached = prefs.getString(hash, null) ?: return false
        return cached == "blocked"
    }

    private fun markSafe(file: File) {
        val hash = computeFileHash(file)
        prefs.edit().putString(hash, "safe").apply()
        scannedSafe.add(file.absolutePath)
    }

    private fun markBlocked(file: File) {
        val hash = computeFileHash(file)
        prefs.edit().putString(hash, "blocked").apply()
        blockedFiles.add(file.absolutePath)
    }

    private fun clearCacheForFile(file: File) {
        val hash = computeFileHash(file)
        prefs.edit().remove(hash).apply()
        scannedSafe.remove(file.absolutePath)
        blockedFiles.remove(file.absolutePath)
    }

    // ════════════════════════════════════════════════════
    // downloadAndScan
    // Scan before saving — the safest approach
    // ════════════════════════════════════════════════════
    @ReactMethod
    fun downloadAndScan(
        fileUrl: String, filename: String,
        apiKey: String, backendUrl: String,
        promise: Promise
    ) {
        Thread {
            try {
                println("\n📥 downloadAndScan: $filename")

                val scanUrl  = URL("$backendUrl/scan-file")
                val scanConn = scanUrl.openConnection() as HttpURLConnection
                scanConn.requestMethod = "POST"
                scanConn.setRequestProperty("Content-Type", "application/json")
                scanConn.setRequestProperty("X-API-KEY", apiKey)
                scanConn.doOutput       = true
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
                    println("⛔ Blocked before download: $filename | $reason")
                    val result = WritableNativeMap()
                    result.putBoolean("allowed", false)
                    result.putString("reason",   reason)
                    promise.resolve(result)
                    return@Thread
                }

                // Safe — download and save
                println("✅ Safe — downloading: $filename")
                val destFile = File(downloadsDir, filename)

                val dlConn = (URL(fileUrl).openConnection() as HttpURLConnection).apply {
                    setRequestProperty("User-Agent", "Mozilla/5.0")
                    connectTimeout = 15000
                    readTimeout    = 120000
                }

                dlConn.inputStream.use { input ->
                    FileOutputStream(destFile).use { output ->
                        val buffer = ByteArray(8192)
                        var bytesRead: Int
                        while (input.read(buffer).also { bytesRead = it } != -1) {
                            output.write(buffer, 0, bytesRead)
                        }
                    }
                }
                dlConn.disconnect()

                markSafe(destFile)
                println("💾 Saved: ${destFile.absolutePath}")

                sendEvent("onFileDownloaded", mapOf(
                    "name"    to filename,
                    "path"    to destFile.absolutePath,
                    "allowed" to true,
                ))

                val result = WritableNativeMap()
                result.putBoolean("allowed", true)
                result.putString("path",     destFile.absolutePath)
                result.putString("reason",   "Clean — saved successfully")
                promise.resolve(result)

            } catch (e: Exception) {
                println("❌ downloadAndScan error: ${e.message}")
                promise.reject("DOWNLOAD_ERROR", e.message)
            }
        }.start()
    }

    // ════════════════════════════════════════════════════
    // startWatching — FileObserver for auto-scan on new files
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

                // Skip if already processed
                if (isKnownSafe(file))    return
                if (isKnownBlocked(file)) return

                println("👁️ New file detected: $path")
                autoScanFile(file)
            }
        }
        fileObserver?.startWatching()
        println("👁️ FileObserver started on: ${downloadsDir.absolutePath}")
    }

    @ReactMethod
    fun stopWatching() {
        fileObserver?.stopWatching()
        fileObserver = null
        println("👁️ FileObserver stopped")
    }

    // ════════════════════════════════════════════════════
    // autoScanFile — used by FileObserver for background auto-scan
    // ════════════════════════════════════════════════════
    private fun autoScanFile(file: File) {
        Thread {
            try {
                val ext = file.extension.lowercase()

                // Fast block — no server call needed
                if (ext in dangerousExtensions) {
                    println("⛔ Auto-blocked by extension: ${file.name}")
                    file.delete()
                    markBlocked(file)
                    sendEvent("onFileDangerous", mapOf(
                        "name"   to file.name,
                        "reason" to "Dangerous file type (.$ext) — blocked automatically",
                    ))
                    return@Thread
                }

                // Fast pass — safe extension, verify magic bytes only
                if (ext in safeExtensions) {
                    val header = file.inputStream().use { it.readNBytes(16) }
                    if (!looksLikeMaliciousMagic(header)) {
                        markSafe(file)
                        sendEvent("onFileScanned", mapOf(
                            "name"    to file.name,
                            "allowed" to true,
                            "reason"  to "Safe file type",
                        ))
                        return@Thread
                    }
                    // Magic bytes suspicious even though extension looks safe → full scan
                }

                // Full scan via server
                val maxBytes = 1 * 1024 * 1024
                val bytes = file.inputStream().use { s ->
                    val buf  = ByteArray(maxBytes)
                    val read = s.read(buf)
                    if (read > 0) buf.copyOf(read) else byteArrayOf()
                }
                val base64 = Base64.encodeToString(bytes, Base64.NO_WRAP)

                val conn = (URL("$currentBackend/scan-local-file").openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    setRequestProperty("Content-Type", "application/json")
                    setRequestProperty("X-API-KEY", currentApiKey)
                    doOutput       = true
                    connectTimeout = 15000
                    readTimeout    = 30000
                }

                val body = """{"filename":"${file.name}","content":"$base64","size":${file.length()}}"""
                conn.outputStream.write(body.toByteArray())
                val response = conn.inputStream.bufferedReader().readText()
                conn.disconnect()

                val allowed = response.contains("\"allowed\":true")
                val reason  = Regex("\"reason\":\"([^\"]+)\"")
                    .find(response)?.groupValues?.get(1) ?: ""

                if (!allowed) {
                    println("⛔ Auto-blocked & deleted: ${file.name} | $reason")
                    file.delete()
                    markBlocked(file)
                    sendEvent("onFileDangerous", mapOf("name" to file.name, "reason" to reason))
                } else {
                    markSafe(file)
                    sendEvent("onFileScanned", mapOf("name" to file.name, "allowed" to true))
                }

            } catch (e: Exception) {
                println("❌ autoScanFile error: ${e.message}")
            }
        }.start()
    }

    // Quick local magic bytes check (no server call)
    private fun looksLikeMaliciousMagic(header: ByteArray): Boolean {
        if (header.size < 2) return false
        // MZ header = Windows PE executable
        if (header[0] == 0x4D.toByte() && header[1] == 0x5A.toByte()) return true
        // ELF header = Linux executable
        if (header.size >= 4 &&
            header[0] == 0x7F.toByte() &&
            header[1] == 'E'.code.toByte() &&
            header[2] == 'L'.code.toByte() &&
            header[3] == 'F'.code.toByte()) return true
        // Unix shebang
        if (header[0] == '#'.code.toByte() && header[1] == '!'.code.toByte()) return true
        return false
    }

    // ════════════════════════════════════════════════════
    // scanDownloadsFolder — PARALLEL scan with progress
    // ════════════════════════════════════════════════════
    @ReactMethod
    fun scanDownloadsFolder(apiKey: String, backendUrl: String, promise: Promise) {
        Thread {
            try {
                val files = (downloadsDir.listFiles() ?: emptyArray())
                    .filter { it.isFile }
                    .sortedByDescending { it.lastModified() }

                val total   = files.size
                val counter = AtomicInteger(0)
                val results = WritableNativeArray()
                val lock    = Any()

                println("\n📂 scanDownloadsFolder: $total files | Parallel mode")

                // Use thread pool: 4 threads for parallel scanning
                val executor = Executors.newFixedThreadPool(
                    minOf(4, maxOf(1, total))
                )

                val futures = files.map { file ->
                    executor.submit<WritableNativeMap> {
                        val result = WritableNativeMap()
                        result.putString("name", file.name)
                        result.putString("path", file.absolutePath)
                        result.putDouble("size", file.length().toDouble())

                        val ext = file.extension.lowercase()
                        val done = counter.incrementAndGet()

                        // ── Send progress event ────────────────────
                        sendEvent("onScanProgress", mapOf(
                            "current"  to done,
                            "total"    to total,
                            "filename" to file.name,
                        ))

                        // ── Check persistent cache first ──────────
                        if (isKnownSafe(file)) {
                            result.putBoolean("allowed", true)
                            result.putString("reason",  "Previously scanned — clean")
                            return@submit result
                        }
                        if (isKnownBlocked(file)) {
                            result.putBoolean("allowed", false)
                            result.putString("reason",  "Previously detected as dangerous")
                            return@submit result
                        }

                        // ── Fast block by extension ───────────────
                        if (ext in dangerousExtensions) {
                            println("⛔ [${done}/$total] Extension blocked: ${file.name}")
                            file.delete()
                            markBlocked(file)
                            result.putBoolean("allowed", false)
                            result.putString("reason",  "Dangerous file type (.$ext)")
                            return@submit result
                        }

                        // ── Fast pass for safe extensions ─────────
                        if (ext in safeExtensions) {
                            val header = runCatching {
                                file.inputStream().use { it.readNBytes(16) }
                            }.getOrDefault(byteArrayOf())

                            if (!looksLikeMaliciousMagic(header)) {
                                println("✅ [${done}/$total] Safe extension: ${file.name}")
                                markSafe(file)
                                result.putBoolean("allowed", true)
                                result.putString("reason",  "Safe file type (.$ext)")
                                return@submit result
                            }
                            // Fall through to full scan — magic bytes suspicious
                        }

                        // ── Full server scan ──────────────────────
                        println("🔬 [${done}/$total] Full scan: ${file.name}")
                        try {
                            val maxBytes = 1 * 1024 * 1024
                            val bytes = file.inputStream().use { s ->
                                val buf  = ByteArray(maxBytes)
                                val read = s.read(buf)
                                if (read > 0) buf.copyOf(read) else byteArrayOf()
                            }
                            val base64 = Base64.encodeToString(bytes, Base64.NO_WRAP)

                            val conn = (URL("$backendUrl/scan-local-file").openConnection() as HttpURLConnection).apply {
                                requestMethod = "POST"
                                setRequestProperty("Content-Type", "application/json")
                                setRequestProperty("X-API-KEY", apiKey)
                                doOutput       = true
                                connectTimeout = 15000
                                readTimeout    = 30000
                            }
                            val body = """{"filename":"${file.name}","content":"$base64","size":${file.length()}}"""
                            conn.outputStream.write(body.toByteArray())
                            val response = conn.inputStream.bufferedReader().readText()
                            conn.disconnect()

                            val allowed = response.contains("\"allowed\":true")
                            val reason  = Regex("\"reason\":\"([^\"]+)\"")
                                .find(response)?.groupValues?.get(1) ?: ""

                            if (allowed) {
                                markSafe(file)
                            } else {
                                file.delete()
                                markBlocked(file)
                                println("⛔ [${done}/$total] Deleted: ${file.name} | $reason")
                            }

                            result.putBoolean("allowed", allowed)
                            result.putString("reason",  reason)

                        } catch (e: Exception) {
                            // On scan error: keep the file, mark as unknown
                            println("⚠️ Scan error for ${file.name}: ${e.message}")
                            result.putBoolean("allowed", true)
                            result.putString("reason",  "Scan error — kept file")
                        }

                        result
                    }
                }

                // Wait for all scans to finish (max 5 minutes)
                executor.shutdown()
                executor.awaitTermination(5, TimeUnit.MINUTES)

                // Collect all results
                synchronized(lock) {
                    futures.forEach { future ->
                        runCatching { results.pushMap(future.get()) }
                    }
                }

                // Send completion event
                val blocked = (0 until results.size()).count {
                    !(results.getMap(it)?.getBoolean("allowed") ?: true)
                }
                sendEvent("onScanComplete", mapOf(
                    "total"   to total,
                    "blocked" to blocked,
                    "safe"    to (total - blocked),
                ))

                println("✅ scanDownloadsFolder done: $total files, $blocked blocked")
                promise.resolve(results)

            } catch (e: Exception) {
                promise.reject("SCAN_ERROR", e.message)
            }
        }.start()
    }

    // ════════════════════════════════════════════════════
    // getDownloadsList
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
                val safe    = isKnownSafe(file)    || scannedSafe.contains(file.absolutePath)
                val blocked = isKnownBlocked(file) || blockedFiles.contains(file.absolutePath)
                item.putString("name",     file.name)
                item.putString("path",     file.absolutePath)
                item.putDouble("size",     file.length().toDouble())
                item.putDouble("modified", file.lastModified().toDouble())
                item.putBoolean("blocked", blocked)
                item.putBoolean("safe",    safe)
                list.pushMap(item)
            }
            promise.resolve(list)
        } catch (e: Exception) {
            promise.reject("LIST_ERROR", e.message)
        }
    }

    // ════════════════════════════════════════════════════
    // deleteFile
    // ════════════════════════════════════════════════════
    @ReactMethod
    fun deleteFile(filePath: String, promise: Promise) {
        try {
            val file = File(filePath)
            if (file.exists() && file.absolutePath.startsWith(downloadsDir.absolutePath)) {
                clearCacheForFile(file)
                file.delete()
                promise.resolve(true)
            } else {
                promise.resolve(false)
            }
        } catch (e: Exception) {
            promise.reject("DELETE_ERROR", e.message)
        }
    }

    // ════════════════════════════════════════════════════
    // clearScanCache — let parent reset all scan history
    // ════════════════════════════════════════════════════
    @ReactMethod
    fun clearScanCache(promise: Promise) {
        prefs.edit().clear().apply()
        scannedSafe.clear()
        blockedFiles.clear()
        promise.resolve(true)
        println("🗑️ Scan cache cleared")
    }

    // ════════════════════════════════════════════════════
    // Events
    // ════════════════════════════════════════════════════
    private fun sendEvent(eventName: String, data: Map<String, Any>) {
        try {
            val params = WritableNativeMap()
            for ((k, v) in data) when (v) {
                is String  -> params.putString(k,  v)
                is Boolean -> params.putBoolean(k, v)
                is Int     -> params.putInt(k,     v)
                is Double  -> params.putDouble(k,  v)
            }
            reactContext
                .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java)
                .emit(eventName, params)
        } catch (e: Exception) {
            println("sendEvent error: ${e.message}")
        }
    }

    @ReactMethod fun addListener(eventName: String) {}
    @ReactMethod fun removeListeners(count: Int) {}
}