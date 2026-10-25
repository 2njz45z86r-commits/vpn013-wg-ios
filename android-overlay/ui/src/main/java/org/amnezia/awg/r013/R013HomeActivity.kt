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
    private lateinit var currentPing: MaterialButton
    private lateinit var allPing: MaterialButton
    private lateinit var countLabel: TextView
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
    private val permissionResult = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val pending = pendingTunnel; pendingTunnel = null
        if (pending != null && result.resultCode == RESULT_OK) connect(pending, true)
        else feedback("Подключение отменено")
    }
    private val qrResult = registerForActivityResult(ScanContract()) { result ->
        result.contents?.let { text ->
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
        inside.addView(summaryDetails); card.addView(inside); content.addView(card, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(12) })
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
    override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); setIntent(intent); handleSharedFile(intent) }
    override fun onResume() {
        super.onResume()
        ClientUpdates.resumePendingInstall(this)
    }
    private fun handleSharedFile(intent: Intent) {
        @Suppress("DEPRECATION") val uri = if (intent.action == Intent.ACTION_SEND) intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM) else if (intent.action == Intent.ACTION_VIEW) intent.data else null
        if (uri != null && uri.scheme in listOf("content", "file")) { intent.action = null; importFile(uri) }
    }
    private fun importFile(uri: Uri) { lifecycleScope.launch { TunnelImporter.importTunnel(contentResolver, uri) { feedback(it.toString()); listSignature = "" } } }
    private fun addMenu() {
        val dialog = BottomSheetDialog(this)
        val box = vertical().apply { setPadding(dp(20), dp(12), dp(20), dp(24)) }
        box.addView(text("Добавить профиль", 22, true).apply { setPadding(dp(12), dp(12), dp(12), dp(16)) })
        val items = listOf<Pair<String, () -> Unit>>(
            "Купить конфигурацию" to { open(ClientProtocol.BOT) },
            "1 час бесплатно" to { open(ClientProtocol.WEBSITE) },
            "Создать режим Авто" to { createAuto() },
            "Импорт из файла или ZIP" to { fileResult.launch(arrayOf("*/*")) },
            "Сканировать QR-код" to { qrResult.launch(ScanOptions().setOrientationLocked(false).setBeepEnabled(false).setPrompt("Конфигурация AmneziaWG")) },
            "Создать с нуля" to { startActivity(Intent(this, TunnelCreatorActivity::class.java)) }
        )
        items.forEach { (label, action) -> box.addView(button(label) { dialog.dismiss(); action() }.apply { gravity = Gravity.START or Gravity.CENTER_VERTICAL; minimumHeight = dp(52) }) }
        dialog.setContentView(box); dialog.show()
    }
    private fun settings() {
        MaterialAlertDialogBuilder(this).setTitle("VPN013").setItems(arrayOf("Обновить конфигурации", "Проверить обновление приложения", "Настройки и журнал", "Купить конфигурацию")) { _, index ->
            when (index) {
                0 -> lifecycleScope.launch { try { feedback("Проверяем обновления конфигураций…"); feedback(ClientUpdates.refreshOrders()) ; listSignature = "" } catch (e: Exception) { feedback(e.message ?: "Обновление не выполнено") } }
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
        val tunnels = Application.getTunnelManager().getTunnels().toList()
        val signature = tunnels.joinToString { it.name + it.state.toString() + it.connectionStatus.toString() } + connecting + pings.toString()
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
                isChecked = tunnel.state == Tunnel.State.UP; isEnabled = !connecting; minimumWidth = dp(48); minimumHeight = dp(48)
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
        if (connecting) return
        if (up) { val prepare = GoBackend.VpnService.prepare(this); if (prepare != null) { pendingTunnel = tunnel; permissionResult.launch(prepare); return } }
        connecting = true
        lifecycleScope.launch {
            try { renderRows(true); tunnel.setStateAsync(if (up) Tunnel.State.UP else Tunnel.State.DOWN) }
            catch (e: Exception) { feedback(e.message ?: "Не удалось изменить подключение") }
            finally { connecting = false; listSignature = ""; renderCurrent(); renderRows() }
        }
    }
    private suspend fun renderCurrent() {
        val backend = Application.getBackend() as GoBackend
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
