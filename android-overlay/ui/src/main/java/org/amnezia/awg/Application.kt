/*
 * Copyright © 2017-2023 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package org.amnezia.awg

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.StrictMode
import android.os.StrictMode.ThreadPolicy
import android.os.StrictMode.VmPolicy
import android.util.Log
import androidx.appcompat.app.AppCompatDelegate
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.preferencesDataStoreFile
import com.google.android.material.color.DynamicColors
import org.amnezia.awg.backend.Backend
import org.amnezia.awg.backend.GoBackend
import org.amnezia.awg.backend.AwgQuickBackend
import org.amnezia.awg.configStore.FileConfigStore
import org.amnezia.awg.model.TunnelManager
import org.amnezia.awg.util.NetworkState
import org.amnezia.awg.util.NetworkType
import org.amnezia.awg.util.RootShell
import org.amnezia.awg.util.ToolsInstaller
import org.amnezia.awg.util.UserKnobs
import org.amnezia.awg.util.applicationScope
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.lang.ref.WeakReference
import java.util.Locale

class Application : android.app.Application() {
    private val futureBackend = CompletableDeferred<Backend>()
    private val coroutineScope = CoroutineScope(Job() + Dispatchers.Main.immediate)
    private var backend: Backend? = null
    private lateinit var rootShell: RootShell
    private lateinit var preferencesDataStore: DataStore<Preferences>
    private lateinit var toolsInstaller: ToolsInstaller
    private lateinit var tunnelManager: TunnelManager
    private lateinit var networkState: NetworkState

    override fun attachBaseContext(context: Context) {
        super.attachBaseContext(context)
        if (BuildConfig.MIN_SDK_VERSION > Build.VERSION.SDK_INT) {
            @Suppress("UnsafeImplicitIntentLaunch")
            val intent = Intent(Intent.ACTION_MAIN)
            intent.addCategory(Intent.CATEGORY_HOME)
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK)
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            startActivity(intent)
            System.exit(0)
        }
    }

    private suspend fun determineBackend(): Backend {
        val backend = GoBackend(applicationContext)
        backend.setApplicationRoutingSource { name ->
            org.amnezia.awg.r013.ApplicationRoutingStore.wireGuard(org.amnezia.awg.r013.ProfileRegistry.get(this).vault, name)
        }
        backend.setServiceRoutingSource { name ->
            org.amnezia.awg.r013.ServiceRoutingStore.wireGuard(org.amnezia.awg.r013.ProfileRegistry.get(this).vault, name, this)
        }
        backend.setAutomaticEnabled(org.amnezia.awg.r013.ProfileRegistry.get(this).automaticEnabled())
        backend.setAutomaticSource { name ->
            org.amnezia.awg.r013.ProfileRegistry.get(this).automaticMembers(name).map { (title, config) ->
                GoBackend.AutoMember(title, config)
            }
        }
        GoBackend.setAlwaysOnCallback { get().applicationScope.launch { get().tunnelManager.restoreState(true) } }
        return backend
    }

    override fun onCreate() {
        Log.i(TAG, USER_AGENT)
        super.onCreate()
        AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES)
        rootShell = RootShell(applicationContext)
        toolsInstaller = ToolsInstaller(applicationContext, rootShell)
        preferencesDataStore = PreferenceDataStoreFactory.create { applicationContext.preferencesDataStoreFile("settings") }
        tunnelManager = TunnelManager(FileConfigStore(applicationContext))
        tunnelManager.onCreate()

        // Initialize network state monitor for auto-reconnection
        networkState = NetworkState(applicationContext) { oldType, newType ->
            Log.i(TAG, "NetworkState callback: Network changed: $oldType -> $newType")
            onNetworkChange(oldType, newType)
        }

        coroutineScope.launch(Dispatchers.IO) {
            try {
                backend = determineBackend()
                futureBackend.complete(backend!!)
                networkState.bindNetworkListener()
            } catch (e: Throwable) {
                Log.e(TAG, "Backend initialization failed (${e.javaClass.simpleName})")
            }
        }

        if (BuildConfig.DEBUG) {
            StrictMode.setVmPolicy(VmPolicy.Builder().detectAll().penaltyLog().build())
            StrictMode.setThreadPolicy(ThreadPolicy.Builder().detectAll().penaltyLog().build())
        }
    }

    override fun onTerminate() {
        networkState.unbindNetworkListener()
        coroutineScope.cancel()
        super.onTerminate()
    }

    /**
     * Called when network changes (e.g., WiFi to Mobile or vice versa).
     * Reconnects active tunnels to ensure VPN connection works on new network.
     */
    private fun onNetworkChange(oldType: NetworkType, newType: NetworkType) {
        Log.i(TAG, "onNetworkChange called: $oldType -> $newType")
        (backend as? GoBackend)?.onPhysicalPathChanged()
        
        if (newType == NetworkType.NONE) {
            Log.i(TAG, "Network lost, waiting for new connection...")
            return
        }

        coroutineScope.launch(Dispatchers.IO) {
            try {
                val backend = getBackend() as GoBackend
                val snapshot = backend.connectionView()
                kotlinx.coroutines.delay(500)
                backend.reconnectIfCurrent(snapshot.profile(), snapshot.revision())
            } catch (_: Exception) {
                Log.w(TAG, "Network reconnection did not complete; user control is preserved")
            }
        }
    }

    companion object {
        val USER_AGENT = String.format(Locale.ENGLISH, "AmneziaWG/%s (Android %d; %s; %s; %s %s; %s)", BuildConfig.VERSION_NAME, Build.VERSION.SDK_INT, if (Build.SUPPORTED_ABIS.isNotEmpty()) Build.SUPPORTED_ABIS[0] else "unknown ABI", Build.BOARD, Build.MANUFACTURER, Build.MODEL, Build.FINGERPRINT)
        private const val TAG = "AmneziaWG/Application"
        private lateinit var weakSelf: WeakReference<Application>

        fun get(): Application {
            return weakSelf.get()!!
        }

        suspend fun getBackend() = get().futureBackend.await()

        fun getRootShell() = get().rootShell

        fun getPreferencesDataStore() = get().preferencesDataStore

        fun getToolsInstaller() = get().toolsInstaller

        fun getTunnelManager() = get().tunnelManager

        fun getCoroutineScope() = get().coroutineScope

        fun getNetworkState() = get().networkState
    }

    init {
        weakSelf = WeakReference(this)
    }
}
