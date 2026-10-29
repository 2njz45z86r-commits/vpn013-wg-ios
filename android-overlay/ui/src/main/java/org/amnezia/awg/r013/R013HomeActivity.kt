// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.snackbar.Snackbar
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.amnezia.awg.Application
import org.amnezia.awg.R
import org.amnezia.awg.activity.MainActivity
import org.amnezia.awg.activity.SettingsActivity
import org.amnezia.awg.activity.TunnelCreatorActivity
import org.amnezia.awg.backend.GoBackend
import org.amnezia.awg.backend.Tunnel
import org.amnezia.awg.model.ObservableTunnel
import org.amnezia.awg.util.TunnelImporter
import java.text.DateFormat
import java.util.Date

/** Native Material surface for the owner-approved R013 list and current server. */
class R013HomeActivity : AppCompatActivity() {
    private val registry by lazy { ProfileRegistry.get(this) }
    private lateinit var root: FrameLayout
    private lateinit var content: LinearLayout
    private lateinit var rows: LinearLayout
    private lateinit var summaryTitle: TextView
    private lateinit var summaryDetails: TextView
    private lateinit var routingDetails: TextView
    private lateinit var currentPing: MaterialButton
    private lateinit var allPing: MaterialButton
    private lateinit var countLabel: TextView
    private lateinit var automaticToggle: MaterialSwitch
    private var applyingAutomatic = false
    private var automaticReady = false
    private var selectedSection = "AMNEZIAWG"
    private val proxyStore by lazy { ProxyRegistry(registry.vault) }
    private var pendingProxy: String? = null
    private val proxyPermission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val id = pendingProxy; pendingProxy = null
        if (id != null && result.resultCode == RESULT_OK) connectProxy(id)
    }
    private var listSignature = ""
    private var currentIdentity = ""
    private var currentHost: String? = null
    private var currentMeasurement: Pair<String, Long?>? = null
    private var pingJob: Job? = null
    private var batchJob: Job? = null
    private var connecting = false
    private var pendingError: String? = null
    private var pendingTunnel: ObservableTunnel? = null
    private val pings = HashMap<String, Pair<String, Long?>>()
    private val fileResult = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> if (uri != null) importFile(uri) }
    private val trialNotificationsPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) {
        NativeTrial.show(this) { listSignature = "" }
    }
    private val permissionResult = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val pending = pendingTunnel; pendingTunnel = null
        if (pending != null && result.resultCode == RESULT_OK) connect(pending, true)
        else feedback("Подключение отменено")
    }
    private val qrResult = registerForActivityResult(ScanContract()) { result ->
        result.contents?.let { text ->
            if (selectedSection != "AMNEZIAWG") {
                val section = ProxyProfile.Section.valueOf(selectedSection)
                launchOffline { "Добавлено профилей: ${proxyStore.importText(section, text).size}" }
                return@let
            }
            lifecycleScope.launch {
                try { val config = withContext(Dispatchers.IO) { ProfileRegistry.parse(text) }
                    askName("Новый профиль", "Профиль") { name -> launchOffline { registry.create(name, config); "Профиль добавлен" } }
                } catch (_: Exception) { feedback("QR не содержит подходящую конфигурацию AmneziaWG") }
            }
        }
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        root = FrameLayout(this).apply { setBackgroundColor(color(R.color.r013_background)) }
        val scroll = ScrollView(this).apply { isFillViewport = true }
        content = vertical().apply { setPadding(dp(20), dp(8), dp(20), dp(20)) }
        scroll.addView(content, FrameLayout.LayoutParams(-1, -2))
        val width = if (resources.configuration.screenWidthDp >= 720) dp(720) else -1
        root.addView(scroll, FrameLayout.LayoutParams(width, -1, Gravity.TOP or Gravity.CENTER_HORIZONTAL))
        setContentView(root)
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
            view.setPadding(bars.left, bars.top, bars.right, maxOf(bars.bottom, ime.bottom)); insets
        }
        WindowCompat.getInsetsController(window, root).isAppearanceLightStatusBars = false
        WindowCompat.getInsetsController(window, root).isAppearanceLightNavigationBars = false
        val toolbar = MaterialToolbar(this).apply {
            title = "VPN013"; setTitleTextColor(color(R.color.r013_text)); setNavigationIcon(R.drawable.ic_r013_settings)
            navigationContentDescription = "Настройки и обновления"; setNavigationIconTint(color(R.color.r013_accent))
            setNavigationOnClickListener { settings() }
            menu.add("Добавить").apply { setIcon(R.drawable.ic_r013_add); setShowAsAction(2) }
            setOnMenuItemClickListener { addMenu(); true }
        }
        content.addView(toolbar, LinearLayout.LayoutParams(-1, dp(64)))
        val tabs = horizontal()
        listOf("HAPP", "INCY", "AMNEZIAWG", "BLACKTEMPLE").forEach { section ->
            tabs.addView(button(UnifiedAutoCoordinator.label(section)) {
                selectedSection = section; listSignature = ""
                lifecycleScope.launch {
                    withContext(Dispatchers.IO) { registry.vault.edit { it.put("selectedSection", section) } }
                    renderRows(true)
                }
            }.apply { textSize = 11f; minWidth = 0; setPadding(dp(2), 0, dp(2), 0) }, LinearLayout.LayoutParams(0, dp(48), 1f))
        }
        content.addView(tabs)
        lifecycleScope.launch {
            selectedSection = withContext(Dispatchers.IO) {
                val active = ProxyVpnService.activeId
                ProxyProfile.Section.values().firstOrNull { kind -> proxyStore.list(kind).any { it.id == active } }?.name
                    ?: registry.vault.read().optString("selectedSection", "AMNEZIAWG").takeIf {
                        it in listOf("AMNEZIAWG", "HAPP", "INCY", "BLACKTEMPLE")
                    } ?: "AMNEZIAWG"
            }
            listSignature = ""
        }
        val automaticRow = horizontal().apply { setPadding(0, dp(8), 0, dp(12)); gravity = Gravity.CENTER_VERTICAL }
        val automaticLabels = vertical().apply {
            addView(text("Режим Авто", 18, true))
            addView(text("Сравнение каждые 5 минут. Выключите, чтобы оставаться на выбранном сервере.", 12).apply {
                setTextColor(color(R.color.r013_secondary)); setPadding(0, dp(4), dp(12), 0)
            })
        }
        automaticRow.addView(automaticLabels, LinearLayout.LayoutParams(0, -2, 1f))
        automaticToggle = MaterialSwitch(this).apply {
            contentDescription = "Режим Авто"; minimumHeight = dp(48); isEnabled = false
            setOnCheckedChangeListener { _, value ->
                if (!automaticReady || applyingAutomatic) return@setOnCheckedChangeListener
                applyAutomatic(value)
            }
        }
        automaticRow.addView(automaticToggle, LinearLayout.LayoutParams(-2, dp(48)))
        content.addView(automaticRow)
        lifecycleScope.launch {
            try { automaticToggle.isChecked = withContext(Dispatchers.IO) { registry.automaticEnabled() }; automaticReady = true; automaticToggle.isEnabled = true }
            catch (_: Exception) { feedback("Не удалось прочитать настройку Авто. Откройте настройки и повторите.") }
        }
        val card = MaterialCardView(this).apply {
            radius = dp(14).toFloat(); cardElevation = 0f; strokeWidth = dp(1); strokeColor = color(R.color.r013_separator)
            setCardBackgroundColor(color(R.color.r013_background))
        }
        val inside = vertical().apply { setPadding(dp(16), dp(12), dp(12), dp(16)) }
        val top = horizontal()
        summaryTitle = text("VPN отключён", 22, true)
        top.addView(summaryTitle, LinearLayout.LayoutParams(0, -2, 1f))
        currentPing = iconButton(R.drawable.ic_r013_ping, "Проверить пинг текущего сервера") { pingCurrent() }
        top.addView(currentPing, LinearLayout.LayoutParams(dp(48), dp(48)))
        inside.addView(top)
        summaryDetails = text("Выберите профиль ниже", 14).apply { setTextColor(color(R.color.r013_secondary)); setPadding(0, dp(4), 0, 0) }
        inside.addView(summaryDetails)
        routingDetails = text("Российские IP-сети — напрямую; остальные — через VPN", 12).apply {
            setTextColor(color(R.color.r013_secondary)); setPadding(0, dp(6), 0, 0)
        }
        inside.addView(routingDetails)
        card.addView(inside); content.addView(card, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(12) })
        val heading = horizontal().apply { setPadding(0, dp(20), 0, dp(8)) }
        countLabel = text("Профили", 18, true)
        heading.addView(countLabel, LinearLayout.LayoutParams(0, -2, 1f))
        allPing = button("Проверить пинг") { pingAll() }
        heading.addView(allPing, LinearLayout.LayoutParams(-2, -2))
        content.addView(heading)
        content.addView(text("Пинг адреса сервера · по текущему маршруту", 12).apply { setTextColor(color(R.color.r013_secondary)); setPadding(0, 0, 0, dp(12)) })
        rows = vertical(); content.addView(rows)
        val footer = button("Разработчик · @R013_Support") { open("https://t.me/R013_Support") }.apply {
            textSize = 12f; icon = getDrawable(R.drawable.ic_r013_telegram); iconSize = dp(14); setTextColor(color(R.color.r013_secondary))
        }
        content.addView(footer, LinearLayout.LayoutParams(-2, -2).apply { gravity = Gravity.CENTER_HORIZONTAL; topMargin = dp(24) })
        lifecycleScope.launch { repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (true) {
                try { renderCurrent(); renderRows() }
                catch (_: Exception) { summaryDetails.text = "Не удалось прочитать защищённые данные. Откройте настройки и повторите." }
                try { if (ClientUpdates.applyPending()) renderRows() }
                catch (e: Exception) { if (pendingError != e.message) { pendingError = e.message; feedback(e.message ?: "Обновление конфигураций отложено") } }
                delay(2000)
            }
        } }
        handleSharedFile(intent)
        lifecycleScope.launch { ClientUpdates.checkDaily(this@R013HomeActivity) { message -> feedback(message) } }
    }
    override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); setIntent(intent); handleSharedFile(intent); TrialExpiryNotifications.handleOpen(this,intent) }
    override fun onResume() {
        super.onResume()
        ClientUpdates.resumePendingInstall(this)
        TrialExpiryNotifications.scheduleAll(this)
        TrialExpiryNotifications.handleOpen(this,intent)
        NativeTrial.resumeRenewal(this) { listSignature = "" }
    }
    private fun handleSharedFile(intent: Intent) {
        @Suppress("DEPRECATION") val uri = if (intent.action == Intent.ACTION_SEND) intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM) else if (intent.action == Intent.ACTION_VIEW) intent.data else null
        if (uri != null && uri.scheme in listOf("content", "file")) { intent.action = null; importFile(uri) }
    }
    private fun importFile(uri: Uri) {
        if (selectedSection != "AMNEZIAWG") {
            val section = ProxyProfile.Section.valueOf(selectedSection)
            lifecycleScope.launch {
                try {
                    val text = withContext(Dispatchers.IO) { contentResolver.openInputStream(uri)!!.use { input ->
                        val output = java.io.ByteArrayOutputStream(); val buffer = ByteArray(8192)
                        while (true) { val count = input.read(buffer); if (count < 0) break
                            require(output.size() + count <= 1_048_576); output.write(buffer, 0, count) }
                        Charsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                            .decode(java.nio.ByteBuffer.wrap(output.toByteArray())).toString()
                    } }
                    OfflineChanges.apply { proxyStore.importText(section, text) }; listSignature = ""; renderRows()
                } catch (_: Exception) { feedback("Файл не содержит поддерживаемую конфигурацию. Прежние профили сохранены.") }
            }; return
        }
        lifecycleScope.launch { TunnelImporter.importTunnel(contentResolver, uri) { feedback(it.toString()); listSignature = "" } }
    }
    private fun addMenu() {
        if (selectedSection != "AMNEZIAWG") { proxyAddMenu(); return }
        val dialog = BottomSheetDialog(this)
        val box = vertical().apply { setPadding(dp(20), dp(12), dp(20), dp(24)) }
        box.addView(text("Добавить профиль", 22, true).apply { setPadding(dp(12), dp(12), dp(12), dp(16)) })
        val items = listOf<Pair<String, () -> Unit>>(
            "Купить конфигурацию" to { open(ClientProtocol.BOT) },
            NativeTrial.LABEL to {
                val notificationState=getSharedPreferences("trial-notification-permission",MODE_PRIVATE)
                if (android.os.Build.VERSION.SDK_INT >= 33 && !notificationState.getBoolean("asked",false) && androidx.core.content.ContextCompat.checkSelfPermission(this, android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                    notificationState.edit().putBoolean("asked",true).apply()
                    trialNotificationsPermission.launch(android.Manifest.permission.POST_NOTIFICATIONS)
                } else NativeTrial.show(this) { listSignature = "" }
            },
            "Продлить конфигурацию" to { NativeTrial.renewalMenu(this) },
            "Создать режим Авто" to { createAuto() },
            "Импорт из файла или ZIP" to { fileResult.launch(arrayOf("*/*")) },
            "Сканировать QR-код" to { qrResult.launch(ScanOptions().setOrientationLocked(false).setBeepEnabled(false).setPrompt("Конфигурация AmneziaWG")) },
            "Создать с нуля" to { startActivity(Intent(this, TunnelCreatorActivity::class.java)) }
        )
        items.forEach { (label, action) -> box.addView(button(label) { dialog.dismiss(); action() }.apply { gravity = Gravity.START or Gravity.CENTER_VERTICAL; minimumHeight = dp(52) }) }
        dialog.setContentView(ScrollView(this).apply { addView(box) }); dialog.show()
    }
    private fun settings() {
        MaterialAlertDialogBuilder(this).setTitle("VPN013").setItems(arrayOf("Обновить конфигурации", "Проверить обновление приложения", "Настройки и журнал", "Купить конфигурацию")) { _, index ->
            when (index) {
                0 -> lifecycleScope.launch { try {
                    feedback("Проверяем обновления конфигураций…")
                    val ordinary = ClientUpdates.refreshOrders()
                    val count = OfflineChanges.apply { var count = 0
                        for (source in proxyStore.sources()) count += proxyStore.reconcile(source, ProxySubscription.fetch(source)); count }
                    feedback("$ordinary · Профилей подписок: $count"); listSignature = ""
                } catch (_: Exception) { feedback("Обновление не выполнено. Отключите VPN и проверьте доступность подписки. Прежние профили сохранены.") } }
                1 -> ClientUpdates.offerUpdate(this)
                2 -> startActivity(Intent(this, SettingsActivity::class.java))
                3 -> open(ClientProtocol.BOT)
            }
        }.setNegativeButton("Закрыть", null).show()
    }
    private fun createAuto() {
        MaterialAlertDialogBuilder(this).setTitle("Создать режим Авто?")
            .setMessage("Используются 1–30 обычных профилей из этого приложения. После двух неудачных проверок подключения или подтверждённой задержки больше 1200 мс Авто выберет следующий. Ключи и настройки исходных профилей сохранятся. Существующий режим Авто будет заменён. При одном сервере резерва нет.")
            .setPositiveButton("Создать") { _, _ -> launchOffline { val name = registry.createAuto(); "Создан $name" } }.setNegativeButton("Отмена", null).show()
    }
    private fun launchOffline(action: () -> String) { lifecycleScope.launch {
        try { val message = OfflineChanges.apply(action); listSignature = ""; renderRows(); feedback(message) }
        catch (e: Exception) { feedback(e.message ?: "Изменение не выполнено. Прежние профили сохранены.") }
    } }
    private suspend fun renderRows(force: Boolean = false) {
        if (selectedSection != "AMNEZIAWG") { renderProxyRows(); return }
        val tunnels = Application.getTunnelManager().getTunnels().toList()
        val signature = tunnels.joinToString { it.name + it.state.toString() + it.connectionStatus.toString() } + connecting + applyingAutomatic + pings.toString()
        if (!force && signature == listSignature) return
        listSignature = signature; rows.removeAllViews(); countLabel.text = "Профили · ${tunnels.size}"
        allPing.isEnabled = tunnels.isNotEmpty() && batchJob?.isActive != true
        if (tunnels.isEmpty()) {
            rows.addView(text("Добавьте конфигурацию", 22, true).apply { gravity = Gravity.CENTER; setPadding(0, dp(40), 0, dp(8)) })
            rows.addView(text("Импортируйте .conf или ZIP, либо отсканируйте QR-код", 16).apply { gravity = Gravity.CENTER; setTextColor(color(R.color.r013_secondary)) })
            rows.addView(iconButton(R.drawable.ic_r013_add, "Добавить конфигурацию") { addMenu() }, LinearLayout.LayoutParams(dp(64), dp(64)).apply { gravity = Gravity.CENTER_HORIZONTAL; topMargin = dp(24) }); return
        }
        for (tunnel in tunnels) {
            val row = horizontal().apply { minimumHeight = dp(76); setPadding(dp(12), dp(10), dp(6), dp(10)); if (tunnel.state == Tunnel.State.UP) setBackgroundColor(color(R.color.r013_selected)) }
            val labels = vertical().apply { minimumHeight = dp(48); gravity = Gravity.CENTER_VERTICAL }
            labels.addView(text(tunnel.name, 18, true))
            if (registry.isAuto(tunnel.name)) labels.addView(text("Автоматический выбор", 12).apply { setTextColor(color(R.color.r013_secondary)) })
            else if (tunnel.state == Tunnel.State.UP) labels.addView(text(if (tunnel.connectionStatus == ObservableTunnel.ConnectionStatus.CONNECTED) "Рукопожатие подтверждено" else "Проверяется соединение", 12).apply { setTextColor(color(R.color.r013_secondary)) })
            labels.setOnClickListener { details(tunnel) }; labels.setOnLongClickListener { profileMenu(tunnel); true }; labels.contentDescription = "${tunnel.name}, сведения и настройки"
            row.addView(labels, LinearLayout.LayoutParams(0, -2, 1f))
            val config = tunnel.getConfigAsync(); val fingerprint = ProfileRegistry.digest(config.toAwgQuickString())
            val measured = if (registry.isAuto(tunnel.name)) {
                currentMeasurement?.takeIf { it.first == currentIdentity && (Application.getBackend() as GoBackend).currentProfileName == tunnel.name }
            } else pings[tunnel.name]?.takeIf { it.first == fingerprint }
            val ping = text(if (measured == null) "—" else measured.second?.let { "$it мс" } ?: "н/д", 14).apply { gravity = Gravity.CENTER; minWidth = dp(56); setTextColor(color(R.color.r013_secondary)); contentDescription = "Пинг адреса ${tunnel.name}: $text" }
            row.addView(ping, LinearLayout.LayoutParams(-2, dp(48)).apply { marginStart = dp(8); marginEnd = dp(8) })
            val toggle = MaterialSwitch(this).apply {
                isChecked = tunnel.state == Tunnel.State.UP; isEnabled = !connecting && !applyingAutomatic; minimumWidth = dp(48); minimumHeight = dp(48)
                val states = arrayOf(intArrayOf(-android.R.attr.state_enabled), intArrayOf(android.R.attr.state_checked), intArrayOf())
                thumbTintList = ColorStateList(states, intArrayOf(color(R.color.r013_switch_disabled), color(R.color.r013_background), color(R.color.r013_text)))
                trackTintList = ColorStateList(states, intArrayOf(color(R.color.r013_separator), color(R.color.r013_accent), color(R.color.r013_selected)))
                trackDecorationTintList = ColorStateList(states, intArrayOf(color(R.color.r013_separator), color(R.color.r013_accent), color(R.color.r013_secondary)))
                contentDescription = "VPN ${tunnel.name}"; setOnCheckedChangeListener { _, checked -> connect(tunnel, checked) }
            }
            row.addView(toggle, LinearLayout.LayoutParams(-2, dp(48)))
            rows.addView(row)
            rows.addView(View(this).apply { setBackgroundColor(color(R.color.r013_separator)) }, LinearLayout.LayoutParams(-1, dp(1)))
        }
    }
    private fun details(tunnel: ObservableTunnel) {
        if (registry.isAuto(tunnel.name)) {
            val members = registry.members(tunnel.name)
            MaterialAlertDialogBuilder(this).setTitle(tunnel.name).setMessage(members.joinToString("\n") { it.first } + "\n\nСостав сохранён снимком. Чтобы изменить его после ручного редактирования профилей, пересоздайте Авто.")
                .setPositiveButton("Понятно", null).setNeutralButton("Действия") { _, _ -> profileMenu(tunnel) }.show()
        } else startActivity(Intent(this, MainActivity::class.java).putExtra("selected_tunnel", tunnel.name).putExtra("r013_detail_only", true))
    }
    private fun profileMenu(tunnel: ObservableTunnel) {
        MaterialAlertDialogBuilder(this).setTitle(tunnel.name).setItems(arrayOf("Переименовать", "Удалить")) { _, index ->
            if (index == 0) askName("Переименовать профиль", tunnel.name) { name -> lifecycleScope.launch { try { tunnel.setNameAsync(name); listSignature = ""; renderRows() } catch (e: Exception) { feedback(e.message ?: "Не удалось переименовать") } } }
            else MaterialAlertDialogBuilder(this).setTitle("Удалить «${tunnel.name}»?").setMessage("Удаляется только профиль на этом устройстве. Доступ на сервере и срок не меняются.")
                .setPositiveButton("Удалить") { _, _ -> lifecycleScope.launch { try { tunnel.deleteAsync(); listSignature = ""; renderRows() } catch (e: Exception) { feedback(e.message ?: "Не удалось удалить") } } }.setNegativeButton("Отмена", null).show()
        }.show()
    }
    private fun askName(title: String, initial: String, accept: (String) -> Unit) {
        val input = TextInputEditText(this).apply { setText(initial); maxLines = 1; selectAll() }
        val wrapper = TextInputLayout(this).apply { hint = "Название"; setPadding(dp(20), dp(8), dp(20), 0); addView(input) }
        val dialog = MaterialAlertDialogBuilder(this).setTitle(title).setView(wrapper).setPositiveButton("Сохранить", null).setNegativeButton("Отмена", null).create()
        dialog.setOnShowListener { dialog.getButton(-1).setOnClickListener { val name = input.text.toString().trim(); if (!ProfileRegistry.validName(name)) wrapper.error = "От 1 до 64 букв, цифр, пробелов и обычных знаков" else { dialog.dismiss(); accept(name) } } }; dialog.show()
    }
    private fun connect(tunnel: ObservableTunnel, up: Boolean) {
        if (connecting || applyingAutomatic) return
        if (up) { val prepare = GoBackend.VpnService.prepare(this); if (prepare != null) { pendingTunnel = tunnel; permissionResult.launch(prepare); return } }
        connecting = true
        automaticToggle.isEnabled = false
        lifecycleScope.launch {
            try {
                renderRows(true)
                if (up) UnifiedAutoCoordinator.connect(this@R013HomeActivity, UnifiedAutoCoordinator.Candidate("AMNEZIAWG", tunnel.name))
                else { UnifiedAutoCoordinator.stop(); tunnel.setStateAsync(Tunnel.State.DOWN) }
            }
            catch (e: Exception) { feedback(e.message ?: "Не удалось изменить подключение") }
            finally { connecting = false; automaticToggle.isEnabled = true; listSignature = ""; renderCurrent(); renderRows() }
        }
    }
    private fun applyAutomatic(enabled: Boolean) {
        if (connecting || applyingAutomatic) return
        applyingAutomatic = true; automaticToggle.isEnabled = false
        lifecycleScope.launch {
            try {
                val backend = Application.getBackend() as GoBackend
                OfflineChanges.lock.withLock {
                    withContext(Dispatchers.IO) { registry.setAutomaticEnabled(enabled); backend.setAutomaticEnabled(enabled) }
                }
                listSignature = ""; renderCurrent(); renderRows()
            } catch (_: Exception) {
                feedback("Не удалось применить Авто. Повторите действие; активный VPN сохранён.")
                try { automaticToggle.isChecked = withContext(Dispatchers.IO) { registry.automaticEnabled() } } catch (_: Exception) { }
            } finally { applyingAutomatic = false; automaticToggle.isEnabled = !connecting }
        }
    }
    private suspend fun renderCurrent() {
        if (ProxyVpnService.activeId != null || ProxyVpnService.requestedId != null) {
            val id = ProxyVpnService.activeId ?: ProxyVpnService.requestedId
            val record = withContext(Dispatchers.IO) { ProxyProfile.Section.values().flatMap { proxyStore.list(it) }.singleOrNull { it.id == id } }
            summaryTitle.text = record?.profile?.name ?: "Подключение…"
            val stats = withContext(Dispatchers.IO) { ProxyVpnService.statistics() }
            summaryDetails.text = buildString {
                record?.profile?.let { append(UnifiedAutoCoordinator.label(it.section.name)); append(" · ${it.host}:${it.port}\n") }
                append(UnifiedAutoCoordinator.status ?: "Проверяется подключение")
                stats?.let { append("\n↓ ${bytes(it.optLong("rx"))}  ↑ ${bytes(it.optLong("tx"))}") }
            }
            routingDetails.text = if (android.os.Build.VERSION.SDK_INT >= 33) "Российские IP-сети — напрямую; остальные — через VPN"
                else "Все IP-сети — через VPN; исключения российских сетей требуют Android 13 или новее"
            currentPing.isEnabled = true; currentPing.contentDescription = "Отключить VPN"
            currentPing.setOnClickListener { lifecycleScope.launch { UnifiedAutoCoordinator.stop(); listSignature = ""; renderCurrent(); renderRows(true) } }
            return
        }
        currentPing.setOnClickListener { pingCurrent() }
        currentPing.contentDescription = "Проверить пинг текущего сервера"
        val backend = Application.getBackend() as GoBackend
        routingDetails.text = backend.russianRoutingStatus
        val snapshot = withContext(Dispatchers.IO) {
            val live = backend.connectionView()
            val profile = live.profile(); val config = live.config(); val member = live.member()
            val statistics = live.statistics()
            val hs = statistics?.peers()?.mapNotNull { statistics.peer(it)?.latestHandshakeEpochMillis() }?.maxOrNull()?.takeIf { it > 0 && it <= System.currentTimeMillis() + 60_000 }
            val endpoints = config?.peers?.mapNotNull { it.endpoint.orElse(null)?.toString() }.orEmpty()
            val host = config?.peers?.firstOrNull()?.endpoint?.orElse(null)?.host
            Current(profile, member, endpoints, host, statistics?.takeIf { it.peers().isNotEmpty() }?.totalRx(), statistics?.takeIf { it.peers().isNotEmpty() }?.totalTx(), hs, live.revision(), live.hourlySummary())
        }
        val identity = "${snapshot.profile}|${snapshot.member}|${snapshot.endpoints}|${snapshot.revision}"
        if (identity != currentIdentity) { currentIdentity = identity; currentHost = snapshot.host; pingJob?.cancel(); currentMeasurement = null; listSignature = ""; currentPing.text = ""; currentPing.icon = getDrawable(R.drawable.ic_r013_ping) }
        summaryTitle.text = snapshot.member ?: snapshot.profile ?: "VPN отключён"
        currentPing.isEnabled = snapshot.host != null && pingJob?.isActive != true
        summaryDetails.text = if (snapshot.profile == null) "Выберите профиль ниже" else buildString {
            if (snapshot.member != null) append("${snapshot.profile} · ")
            append(if (snapshot.host == null) "Подключение к серверу…" else if (snapshot.handshake != null) "Рукопожатие подтверждено" else "VPN запущен · рукопожатие не подтверждено")
            if (snapshot.endpoints.isNotEmpty()) append("\n" + snapshot.endpoints.joinToString(", "))
            if (snapshot.received != null && snapshot.sent != null) append("\n↓ ${bytes(snapshot.received)}  ↑ ${bytes(snapshot.sent)}")
            currentMeasurement?.takeIf { it.first == currentIdentity }?.let { append(it.second?.let { ms -> "\nПинг адреса: $ms мс" } ?: "\nПинг адреса недоступен") }
            snapshot.handshake?.let { append("\nРукопожатие: ${DateFormat.getTimeInstance(DateFormat.MEDIUM).format(Date(it))}") }
            snapshot.hourly?.let { append("\n$it") }
        }
    }
    private fun proxyAddMenu() {
        MaterialAlertDialogBuilder(this).setTitle("Добавить · ${UnifiedAutoCoordinator.label(selectedSection)}")
            .setItems(arrayOf("Вставить конфигурацию или подписку", "Импортировать файл", "Купить конфигурацию", "Сканировать QR")) { _, choice ->
                when(choice) {
                    0 -> {
                        val section = ProxyProfile.Section.valueOf(selectedSection)
                        val input = TextInputEditText(this).apply { hint = "VLESS, HTTPS-подписка, Base64 или JSON Xray"; minLines = 4; maxLines = 8; inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE }
                        MaterialAlertDialogBuilder(this).setTitle("Своя конфигурация").setView(input)
                            .setPositiveButton("Добавить") { _, _ -> launchOffline {
                                val text = ProxySubscription.normalizeInput(input.text.toString())
                                val count = if (text.startsWith("https://", ignoreCase = true)) {
                                    val source = proxyStore.source(section, text); proxyStore.reconcile(source, ProxySubscription.fetch(source))
                                } else proxyStore.importText(section, text).size
                                "Добавлено профилей: $count"
                            } }
                            .setNegativeButton("Отмена", null).show()
                    }
                    1 -> fileResult.launch(arrayOf("text/*", "application/json", "application/octet-stream"))
                    2 -> open(ClientProtocol.BOT)
                    3 -> qrResult.launch(ScanOptions().setOrientationLocked(false).setBeepEnabled(false).setPrompt("Конфигурация VLESS"))
                }
            }.show()
    }
    private suspend fun renderProxyRows() {
        val section = ProxyProfile.Section.valueOf(selectedSection)
        val records = withContext(Dispatchers.IO) { proxyStore.list(section) }
        val signature = selectedSection + records.joinToString { it.id } + ProxyVpnService.activeId + ProxyVpnService.requestedId + UnifiedAutoCoordinator.busy
        if (listSignature == signature) return
        listSignature = signature; rows.removeAllViews(); countLabel.text = "${UnifiedAutoCoordinator.label(selectedSection)} · ${records.size}"
        allPing.isEnabled = false
        if (records.isEmpty()) rows.addView(button("Добавить свою конфигурацию") { proxyAddMenu() })
        for (record in records) {
            val row = horizontal().apply { minimumHeight = dp(76); gravity = Gravity.CENTER_VERTICAL }
            row.addView(text(record.profile.name, 18, true).apply {
                contentDescription = record.profile.name
                setOnLongClickListener {
                    MaterialAlertDialogBuilder(this@R013HomeActivity).setTitle(record.profile.name)
                        .setItems(arrayOf("Маршрутизация приложений", "Удалить")) { _, item ->
                            if (item == 0) proxyApplications(record.id) else launchOffline { proxyStore.delete(record.id); "Профиль удалён" }
                        }.show(); true
                }
            }, LinearLayout.LayoutParams(0, -2, 1f))
            val active = ProxyVpnService.activeId == record.id || ProxyVpnService.requestedId == record.id
            row.addView(button(if (active) "Выключить" else "Включить") {
                if (active) lifecycleScope.launch { UnifiedAutoCoordinator.stop(); listSignature = ""; renderRows(true) }
                else connectProxy(record.id)
            }.apply { isEnabled = !UnifiedAutoCoordinator.busy || active }, LinearLayout.LayoutParams(-2, dp(52)))
            rows.addView(row)
        }
    }
    private fun connectProxy(id: String) {
        val permission = android.net.VpnService.prepare(this)
        if (permission != null) { pendingProxy = id; proxyPermission.launch(permission); return }
        val record = ProxyProfile.Section.values().flatMap { proxyStore.list(it) }.singleOrNull { it.id == id } ?: return
        UnifiedAutoCoordinator.connect(this, UnifiedAutoCoordinator.Candidate(record.profile.section.name, id))
        listSignature = ""
    }
    private fun proxyApplications(id: String) {
        MaterialAlertDialogBuilder(this).setTitle("Маршрутизация приложений")
            .setItems(arrayOf("Все приложения", "Только выбранные", "Кроме выбранных")) { _, choice ->
                if (choice == 0) { launchOffline { ProxyRouting.save(registry.vault, id, ProxyRouting.Rules()); "Маршрутизация сохранена" }; return@setItems }
                val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
                val apps = packageManager.queryIntentActivities(launcher, 0).map { it.activityInfo.applicationInfo }
                    .distinctBy { it.packageName }.filter { it.packageName != packageName }
                    .sortedBy { packageManager.getApplicationLabel(it).toString() }.take(200)
                val previous = ProxyRouting.read(registry.vault, id)
                val checked = BooleanArray(apps.size) { apps[it].packageName in previous.packages }
                MaterialAlertDialogBuilder(this).setTitle(if (choice == 1) "Только выбранные" else "Кроме выбранных")
                    .setMultiChoiceItems(apps.map { packageManager.getApplicationLabel(it).toString() }.toTypedArray(), checked) { _, index, value -> checked[index] = value }
                    .setPositiveButton("Сохранить") { _, _ -> launchOffline {
                        val packages = apps.filterIndexed { index, _ -> checked[index] }.map { it.packageName }.toSet()
                        require(choice != 1 || packages.isNotEmpty()) { "Выберите хотя бы одно приложение" }
                        ProxyRouting.save(registry.vault, id, previous.copy(mode = if (choice == 1) "only" else "except", packages = packages))
                        "Маршрутизация сохранена. VPN013 остаётся в туннеле для проверки подключения."
                    } }.setNegativeButton("Отмена", null).show()
            }.show()
    }
    private data class Current(val profile: String?, val member: String?, val endpoints: List<String>, val host: String?, val received: Long?, val sent: Long?, val handshake: Long?, val revision: Long, val hourly: String?)
    private fun pingCurrent() {
        val host = currentHost ?: return; val identity = currentIdentity
        if (pingJob?.isActive == true) return
        currentPing.isEnabled = false; currentPing.text = "…"; currentPing.icon = null
        pingJob = lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) { try { EndpointPing.measure(host) } catch (_: Exception) { null } }
            if (identity == currentIdentity) { currentMeasurement = identity to result; listSignature = ""; currentPing.text = ""; currentPing.icon = getDrawable(R.drawable.ic_r013_ping); currentPing.isEnabled = true
                feedback(result?.let { "Пинг текущего адреса: $it мс" } ?: "ICMP-ответ не получен. Это не доказывает отказ VPN.")
                renderCurrent() }
        }
    }
    private fun pingAll() {
        if (batchJob?.isActive == true) return
        allPing.isEnabled = false; allPing.text = "Проверяем…"
        batchJob = lifecycleScope.launch {
            val limit = Semaphore(4)
            try { Application.getTunnelManager().getTunnels().toList().filter { !registry.isAuto(it.name) }.map { tunnel -> async {
                val config = tunnel.getConfigAsync(); val fingerprint = ProfileRegistry.digest(config.toAwgQuickString())
                val host = config.peers.firstOrNull()?.endpoint?.orElse(null)?.host
                val result = limit.withPermit { withContext(Dispatchers.IO) { try { host?.let { EndpointPing.measure(it) } } catch (_: Exception) { null } } }
                if (registry.names().contains(tunnel.name) && ProfileRegistry.digest(registry.config(tunnel.name).toAwgQuickString()) == fingerprint) pings[tunnel.name] = fingerprint to result
            } }.awaitAll(); renderRows(true)
            } finally { allPing.text = "Проверить пинг"; allPing.isEnabled = true }
        }
    }
    private fun bytes(n: Long): String = if (n < 1024) "$n Б" else if (n < 1_048_576) "${n / 1024} КБ" else "${n / 1_048_576} МБ"
    private fun color(id: Int) = getColor(id)
    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
    private fun vertical() = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    private fun horizontal() = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
    private fun text(value: String, size: Int, bold: Boolean = false) = TextView(this).apply { text = value; textSize = size.toFloat(); setTextColor(color(R.color.r013_text)); if (bold) setTypeface(typeface, Typeface.BOLD) }
    private fun button(label: String, action: () -> Unit) = MaterialButton(this, null, com.google.android.material.R.attr.borderlessButtonStyle).apply { text = label; isAllCaps = false; minHeight = dp(48); setOnClickListener { action() } }
    private fun iconButton(resource: Int, description: String, action: () -> Unit) = button("") { action() }.apply { icon = getDrawable(resource); iconSize = dp(24); iconPadding = 0; insetTop = 0; insetBottom = 0; setPadding(dp(12), dp(12), dp(12), dp(12)); contentDescription = description; minimumWidth = dp(48) }
    private fun feedback(message: String) { Snackbar.make(root, message, Snackbar.LENGTH_LONG).setTextMaxLines(6).show() }
    private fun open(url: String) { try { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) } catch (_: Exception) { feedback("Не удалось открыть ссылку. Установите браузер или Telegram.") } }
}
