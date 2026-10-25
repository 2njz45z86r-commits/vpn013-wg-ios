// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.Manifest
import android.app.AlarmManager
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.amnezia.awg.Application
import org.amnezia.awg.R
import org.json.JSONObject
import java.io.IOException
import java.net.URL
import java.security.SecureRandom
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.HttpsURLConnection
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** Direct native trial; no browser handoff, no management credential. */
object NativeTrial {
    const val LABEL = "Три дня теста бесплатно"
    const val DURATION = 259200L
    private val token = Regex("^[A-Za-z0-9_-]{43}$")
    private val order = Regex("^[a-f0-9]{12}$")
    private val renewal = Regex("^https://t\\.me/vpn013_com_bot\\?start=trial_[A-Za-z0-9_-]{43}$")
    private val executor = Executors.newSingleThreadExecutor()
    private val networkOwner = AtomicReference<Any?>()
    private val operationBusy = AtomicBoolean()
    fun interface FixtureTransport { suspend fun post(action: String,body: JSONObject,ticket: String?,binary: Boolean): ByteArray }
    @Volatile private var fixture: FixtureTransport?=null
    fun installDebugFixture(value: FixtureTransport?) { check(org.amnezia.awg.BuildConfig.DEBUG);fixture=value }
    fun renewalURL(value: String): String {
        require(renewal.matches(value)) { "Личная ссылка продления не принята" }
        return value
    }
    fun validateTrial(document: JSONObject) {
        if (!document.has("trial")) return
        val value=document.getJSONObject("trial")
        require(value.getLong("durationSeconds")==DURATION)
        renewalURL(value.getString("renewalURL"))
    }
    private fun validateInfo(value: JSONObject, previous: JSONObject? = null): JSONObject {
        require(value.getInt("schema")==1 && value.getString("kind")=="vpn013-native-trial" && value.getString("app")=="vpn013-wg")
        require(order.matches(value.getString("orderID")) && value.getLong("durationSeconds")==DURATION)
        require(value.getString("state") in setOf("provisioning","active","revoking","revoked","expired"))
        require(value.getLong("issuedAt")>0 && value.getLong("expiresAt")>0 && value.getLong("serverTime")>0)
        if (value.getBoolean("isTrial")) require(value.getLong("expiresAt")-value.getLong("issuedAt")==DURATION*1000)
        renewalURL(value.getString("renewalURL"))
        if (previous!=null) require(value.getString("orderID")==previous.getString("orderID") && value.getString("renewalURL")==previous.getString("renewalURL"))
        return value
    }
    private suspend fun request(action: String, body: JSONObject, ticket: String? = null, binary: Boolean = false): ByteArray {
        require(action in setOf("create","info","file"))
        if(ticket!=null) require(token.matches(ticket))
        if(org.amnezia.awg.BuildConfig.DEBUG) fixture?.let { return it.post(action,body,ticket,binary) }
        val payload=body.toString().toByteArray(Charsets.UTF_8);require(payload.size<=2048)
        return suspendCancellableCoroutine { continuation ->
            val owner=Any()
            if(!networkOwner.compareAndSet(null,owner)) {
                continuation.resumeWithException(IOException("Запрос теста уже выполняется"));return@suspendCancellableCoroutine
            }
            val active=AtomicReference<HttpsURLConnection?>()
            executor.submit {
                try {
                    var result: ByteArray?=null
                    for(origin in ClientProtocol.origins) {
                        if(!continuation.isActive) break
                        val connection=URL(origin+"/client/trial/awg/"+action).openConnection() as HttpsURLConnection
                        active.set(connection)
                        try {
                            connection.instanceFollowRedirects=false;connection.useCaches=false
                            connection.connectTimeout=15000;connection.readTimeout=if(binary)95000 else 20000;connection.requestMethod="POST";connection.doOutput=true
                            connection.setRequestProperty("Content-Type","application/json")
                            connection.setRequestProperty("Accept",if(binary) "application/zip" else "application/json")
                            if(ticket!=null) connection.setRequestProperty("Authorization","Bearer $ticket")
                            connection.setFixedLengthStreamingMode(payload.size);connection.outputStream.use { it.write(payload) }
                            val status=connection.responseCode
                            check(status==200 || action=="create" && status==202) { "Тест пока недоступен" }
                            val type=connection.contentType.orEmpty().substringBefore(';')
                            check(type==if(binary) "application/zip" else "application/json") { "Неверный формат ответа" }
                            result=connection.inputStream.use { ArchiveReader.bounded(it,if(binary) 8_388_608 else 32_768) }
                            break
                        } catch(e: IOException) {
                            if(origin==ClientProtocol.origins.last()) throw e
                        } finally { connection.disconnect();active.compareAndSet(connection,null) }
                    }
                    networkOwner.compareAndSet(owner,null)
                    if(continuation.isActive) continuation.resume(result ?: throw IOException("Запрос отменён"))
                } catch(e: Exception) {
                    networkOwner.compareAndSet(owner,null)
                    if(continuation.isActive) continuation.resumeWithException(e)
                } finally { active.getAndSet(null)?.disconnect();networkOwner.compareAndSet(owner,null) }
            }
            continuation.invokeOnCancellation { active.get()?.disconnect() }
        }
    }
    private suspend fun pending(registry: ProfileRegistry): JSONObject = OfflineChanges.lock.withLock {
        registry.vault.edit { root ->
            root.optJSONObject("nativeTrial")?.let { return@edit JSONObject(it.toString()) }
            val bytes=ByteArray(32).also { SecureRandom().nextBytes(it) }
            val nonce=android.util.Base64.encodeToString(bytes,android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP)
            JSONObject().put("requestID",nonce).also { root.put("nativeTrial",it) }
        }
    }
    private suspend fun save(registry: ProfileRegistry, state: JSONObject) = OfflineChanges.lock.withLock { registry.vault.edit { it.put("nativeTrial",JSONObject(state.toString())) } }
    fun show(activity: AppCompatActivity, changed: () -> Unit) {
        if(!operationBusy.compareAndSet(false,true)) return
        var job: Job?=null
        val dialog=MaterialAlertDialogBuilder(activity).setTitle(LABEL).setMessage("Готовим тестовый ZIP…")
            .setNegativeButton("Отмена") { _,_->job?.cancel() }.setCancelable(false).create()
        dialog.show()
        job=activity.lifecycleScope.launch {
            try {
                val registry=ProfileRegistry.get(activity)
                val state=withContext(Dispatchers.IO) { pending(registry) }
                var ticket=state.optString("ticket")
                var info: JSONObject
                if(ticket.isEmpty()) {
                    val response=JSONObject(String(request("create",JSONObject().put("requestID",state.getString("requestID")).put("platform","android")),Charsets.UTF_8))
                    info=validateInfo(response);ticket=response.getString("ticket");require(token.matches(ticket))
                    state.put("ticket",ticket).put("info",info)
                    withContext(Dispatchers.IO) { save(registry,state) }
                } else info=validateInfo(JSONObject(String(request("info",JSONObject(),ticket),Charsets.UTF_8)),state.optJSONObject("info"))
                val until=android.os.SystemClock.elapsedRealtime()+120000L
                while(info.getString("state")=="provisioning" && android.os.SystemClock.elapsedRealtime()<until) {
                    dialog.setMessage("Готовим все серверы. Пожалуйста, подождите…")
                    kotlinx.coroutines.delay(2000)
                    info=validateInfo(JSONObject(String(request("info",JSONObject(),ticket),Charsets.UTF_8)),info)
                }
                state.put("info",info).put("serverOffset",info.getLong("serverTime")-System.currentTimeMillis())
                withContext(Dispatchers.IO) { save(registry,state) }
                if(info.getString("state")=="expired" || info.getLong("expiresAt")<=info.getLong("serverTime")) {
                    dialog.dismiss();showRenewal(activity,info.getString("renewalURL"),info.getString("orderID"));return@launch
                }
                check(info.getString("state")=="active")
                dialog.setMessage("Загружаем и добавляем конфигурации…")
                val bytes=request("file",JSONObject().put("platform","android"),ticket,binary=true)
                val count=withContext(Dispatchers.IO) {
                    val bundle=ArchiveReader.read(bytes)
                    val parsed=bundle.profiles().map { it.name() to ProfileRegistry.parse(it.text()) }
                    val text=bundle.accessDocument() ?: error("Нет привязки теста")
                    val document=ClientProtocol.androidAccess(ClientProtocol.access(text),parsed)
                    validateTrial(document)
                    require(document.getJSONObject("snapshot").getString("orderID")==info.getString("orderID"))
                    require(document.getJSONObject("snapshot").getLong("expiry")==info.getLong("expiresAt"))
                    require(document.getJSONObject("trial").getString("renewalURL")==info.getString("renewalURL"))
                    OfflineChanges.apply { ClientProtocol.apply(registry,document) }
                }
                TrialExpiryNotifications.scheduleAll(activity)
                changed();dialog.dismiss()
                val notificationNote=if(Build.VERSION.SDK_INT>=33 && ContextCompat.checkSelfPermission(activity,Manifest.permission.POST_NOTIFICATIONS)!=PackageManager.PERMISSION_GRANTED)
                    " Уведомления отключены в настройках Android; срок доступа и продление доступны в приложении." else ""
                MaterialAlertDialogBuilder(activity).setTitle(if(info.getBoolean("isTrial")) "Тестовые профили добавлены" else "Конфигурации обновлены")
                    .setMessage("Добавлено профилей: $count. Доступ действует до "+java.text.DateFormat.getDateTimeInstance().format(java.util.Date(info.getLong("expiresAt")))+". Выберите сервер и включите VPN."+notificationNote)
                    .setPositiveButton("Готово",null).show()
            } catch(e: kotlinx.coroutines.CancellationException) { throw e }
            catch(e: Exception) {
                dialog.dismiss()
                val message=if(e is OfflineChanges.ActiveVPNException) "Сначала отключите VPN, затем нажмите кнопку теста ещё раз. Прежние профили сохранены."
                    else "Не удалось завершить загрузку. Прежние профили сохранены. Повторное нажатие продолжит тот же тест и не продлит его срок."
                MaterialAlertDialogBuilder(activity).setTitle("Тест не добавлен").setMessage(message).setPositiveButton("Готово",null).show()
            } finally { dialog.dismiss();operationBusy.set(false) }
        }
        job?.invokeOnCompletion { operationBusy.set(false);activity.runOnUiThread { dialog.dismiss() } }
    }
    private fun openRenewal(activity: AppCompatActivity,url: String,id: String?) {
        activity.lifecycleScope.launch {
            if(id!=null && order.matches(id)) withContext(Dispatchers.IO) { OfflineChanges.lock.withLock {
                ProfileRegistry.get(activity).vault.edit { root ->
                    val binding=root.getJSONObject("orders").optJSONObject(id)
                    if(binding!=null) {
                        val waiting=root.optJSONObject("renewalsAwaitingReturn") ?: JSONObject().also { root.put("renewalsAwaitingReturn",it) }
                        waiting.put(id,binding.getJSONObject("document").getJSONObject("snapshot").getLong("expiry"))
                    }
                }
            } }
            activity.startActivity(Intent(Intent.ACTION_VIEW,Uri.parse(url)))
        }
    }
    private val refreshingRenewal=AtomicBoolean()
    fun resumeRenewal(activity: AppCompatActivity,changed: () -> Unit) {
        if(!refreshingRenewal.compareAndSet(false,true))return
        val task=activity.lifecycleScope.launch {
            try {
                val registry=ProfileRegistry.get(activity)
                val waiting=withContext(Dispatchers.IO) { registry.vault.read().optJSONObject("renewalsAwaitingReturn") ?: JSONObject() }
                for(id in waiting.keys()) {
                    if(!order.matches(id))continue
                    try {
                        ClientUpdates.refreshOrders(id)
                        withContext(Dispatchers.IO) { OfflineChanges.lock.withLock { registry.vault.edit { root ->
                            val binding=root.getJSONObject("orders").optJSONObject(id)
                            val snapshot=binding?.optJSONObject("pending") ?: binding?.getJSONObject("document")?.getJSONObject("snapshot")
                            if(snapshot!=null && snapshot.getLong("expiry")>waiting.getLong(id)) root.optJSONObject("renewalsAwaitingReturn")?.remove(id)
                        } } }
                        TrialExpiryNotifications.scheduleAll(activity);changed()
                    } catch(e: kotlinx.coroutines.CancellationException) { throw e }
                    catch(_: Exception) { /* Unpaid/expired access stays unchanged; retry on a later return. */ }
                }
            } finally { refreshingRenewal.set(false) }
        }
        task.invokeOnCompletion { refreshingRenewal.set(false) }
    }
    fun showRenewal(activity: AppCompatActivity, value: String,id: String?=null) {
        val url=runCatching { renewalURL(value) }.getOrNull() ?: return
        MaterialAlertDialogBuilder(activity).setTitle("Срок доступа закончился")
            .setMessage("Продлите эту конфигурацию в боте. После оплаты и ручного подтверждения прежние профили и ключи сохранятся — повторный импорт не нужен.")
            .setPositiveButton("Продлить конфигурацию") { _,_->openRenewal(activity,url,id) }
            .setNegativeButton("Позже",null).show()
    }
    fun renewalMenu(activity: AppCompatActivity) {
        val registry=ProfileRegistry.get(activity);val orders=registry.vault.read().getJSONObject("orders")
        val items=orders.keys().asSequence().mapNotNull { id ->
            runCatching {
                val document=ClientProtocol.access(orders.getJSONObject(id).getJSONObject("document").toString())
                id to (document.optJSONObject("trial")?.getString("renewalURL")?.let(::renewalURL)
                    ?: ClientProtocol.BOT+"?start=renew_"+id)
            }.getOrNull()
        }.toList()
        if(items.isEmpty()) { activity.startActivity(Intent(Intent.ACTION_VIEW,Uri.parse(ClientProtocol.BOT)));return }
        MaterialAlertDialogBuilder(activity).setTitle("Продлить конфигурацию")
            .setItems(items.map { "Заявка №"+it.first }.toTypedArray()) { _,index->openRenewal(activity,items[index].second,items[index].first) }
            .setNegativeButton("Отмена",null).show()
    }
}

/** Inexact OS alarm; server expiry remains authoritative even if OS delays it. */
object TrialExpiryNotifications {
    private const val CHANNEL="vpn013-trial-expiry"
    private fun alarm(context: Context,id: String): PendingIntent = PendingIntent.getBroadcast(context,0,
        Intent(context,TrialExpiryReceiver::class.java).setAction(context.packageName+".trial-expiry."+id).putExtra("orderID",id),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
    fun scheduleAll(context: Context) {
        runCatching {
            val root=ProfileRegistry.get(context).vault.read();val orders=root.getJSONObject("orders")
            val offset=root.optJSONObject("nativeTrial")?.optLong("serverOffset",0L) ?: 0L
            val manager=context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
            for(id in orders.keys()) {
                runCatching {
                val d=ClientProtocol.access(orders.getJSONObject(id).getJSONObject("document").toString())
                if(!d.has("trial")) continue
                val pending=orders.getJSONObject(id).optJSONObject("pending")
                if(pending!=null)ClientProtocol.snapshot(pending,id)
                val deadline=(pending ?: d.getJSONObject("snapshot")).getLong("expiry")-offset
                val intent=alarm(context,id);manager.cancel(intent)
                if(deadline>System.currentTimeMillis()) {
                    (context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).cancel(id,1)
                    manager.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP,deadline,intent)
                } else expired(context,id)
                }
            }
        }
    }
    fun expired(context: Context,id: String) {
        runCatching {
            require(Regex("^[a-f0-9]{12}$").matches(id))
            val root=ProfileRegistry.get(context).vault.read()
            val d=ClientProtocol.access(root.getJSONObject("orders").getJSONObject(id).getJSONObject("document").toString())
            require(d.has("trial"))
            val offset=root.optJSONObject("nativeTrial")?.optLong("serverOffset",0L) ?: 0L
            val pending=root.getJSONObject("orders").getJSONObject(id).optJSONObject("pending")
            if(pending!=null)ClientProtocol.snapshot(pending,id)
            val expiry=(pending ?: d.getJSONObject("snapshot")).getLong("expiry")
            if(expiry>System.currentTimeMillis()+offset) { scheduleAll(context);return }
            val notices=context.getSharedPreferences("trial-expiry-notifications",Context.MODE_PRIVATE)
            if(notices.getLong(id,0L)==expiry)return
            if(Build.VERSION.SDK_INT>=33 && ContextCompat.checkSelfPermission(context,Manifest.permission.POST_NOTIFICATIONS)!=PackageManager.PERMISSION_GRANTED)return
            val manager=context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            if(Build.VERSION.SDK_INT>=26)manager.createNotificationChannel(NotificationChannel(CHANNEL,"Срок тестового доступа",NotificationManager.IMPORTANCE_DEFAULT))
            val open=Intent(context,R013HomeActivity::class.java).setAction(context.packageName+".trial-renew."+id).putExtra("renewTrialOrder",id)
            val content=PendingIntent.getActivity(context,0,open,PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            manager.notify(id,1,NotificationCompat.Builder(context,CHANNEL).setSmallIcon(R.drawable.ic_r013_settings)
                .setContentTitle("Срок доступа закончился").setContentText("Продлите конфигурацию. Прежние профили и ключи сохранятся.")
                .setAutoCancel(true).setContentIntent(content).addAction(0,"Продлить конфигурацию",content).build())
            // Only public expiry/id notification markers, never keys/tickets.
            notices.edit().putLong(id,expiry).apply()
        }
    }
    fun handleOpen(activity: AppCompatActivity,intent: Intent) {
        val id=intent.getStringExtra("renewTrialOrder") ?: return
        intent.removeExtra("renewTrialOrder")
        runCatching {
            require(Regex("^[a-f0-9]{12}$").matches(id))
            val d=ClientProtocol.access(ProfileRegistry.get(activity).vault.read().getJSONObject("orders").getJSONObject(id).getJSONObject("document").toString())
            NativeTrial.showRenewal(activity,d.getJSONObject("trial").getString("renewalURL"),id)
        }
    }
}

class TrialExpiryReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context,intent: Intent) {
        val id=intent.getStringExtra("orderID")
        if(id!=null) TrialExpiryNotifications.expired(context,id) else TrialExpiryNotifications.scheduleAll(context)
    }
}
