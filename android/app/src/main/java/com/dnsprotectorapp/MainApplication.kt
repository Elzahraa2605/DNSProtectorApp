package com.dnsprotectorapp

import android.app.Application
import com.facebook.react.PackageList
import com.facebook.react.ReactApplication
import com.facebook.react.ReactHost
import com.facebook.react.ReactNativeApplicationEntryPoint.loadReactNative
import com.facebook.react.defaults.DefaultReactHost.getDefaultReactHost

// الإضافات اللازمة لـ Nitro DNS
import com.nitrodns.NitroOkHttpClientFactory
import com.facebook.react.modules.network.OkHttpClientProvider

class MainApplication : Application(), ReactApplication {

  override val reactHost: ReactHost by lazy {
    getDefaultReactHost(
      context = applicationContext,
      packageList = PackageList(this).packages.apply {
        add(FileMonitorPackage())
      },
    )
  }

  override fun onCreate() {
    super.onCreate()
    OkHttpClientProvider.setOkHttpClientFactory(NitroOkHttpClientFactory())
    loadReactNative(this)
  }
}