package com.dnsprotectorapp

import android.app.Application
import com.facebook.react.PackageList
import com.facebook.react.ReactApplication
import com.facebook.react.ReactHost
import com.facebook.react.ReactNativeApplicationEntryPoint.loadReactNative
import com.facebook.react.defaults.DefaultReactHost.getDefaultReactHost

// الإضافات اللازمة لـ Nitro DNS (حقن DoH داخل التطبيق)
import com.nitrodns.NitroOkHttpClientFactory
import com.facebook.react.modules.network.OkHttpClientProvider

class MainApplication : Application(), ReactApplication {

  override val reactHost: ReactHost by lazy {
    getDefaultReactHost(
      context = applicationContext,
      packageList = PackageList(this).packages.apply {
        // هنا ممكن نضيف modules تانية في المستقبل لو احتجنا
      },
    )
  }

  override fun onCreate() {
    super.onCreate()
    
    // حقن Nitro DNS factory لاعتراض كل طلبات الشبكة داخل التطبيق (fetch, WebView, إلخ)
    OkHttpClientProvider.setOkHttpClientFactory(NitroOkHttpClientFactory())
    
    loadReactNative(this)
  }
}