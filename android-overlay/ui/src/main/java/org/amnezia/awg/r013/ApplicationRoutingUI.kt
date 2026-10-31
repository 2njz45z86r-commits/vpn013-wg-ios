// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.content.Intent
import android.view.Gravity
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.doAfterTextChanged
import com.google.android.material.button.MaterialButton
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout

object ApplicationRoutingUI {
    data class Server(val id: String, val title: String)
    private fun AppCompatActivity.dp(value: Int) = (resources.displayMetrics.density * value).toInt()
    fun servers(activity: AppCompatActivity, section: String, entries: List<Server>, next: (Set<String>) -> Unit) {
        val selected = BooleanArray(entries.size)
        lateinit var dialog: AlertDialog
        fun update() { dialog.getButton(-1)?.apply { isEnabled = selected.any { it }; text = "Далее (${selected.count { it }})" } }
        val actions = LinearLayout(activity).apply { orientation = LinearLayout.HORIZONTAL }
        for ((label, value, key) in listOf(Triple("Выбрать все", true, "all"), Triple("Снять выбор", false, "clear"))) {
            actions.addView(MaterialButton(activity, null, com.google.android.material.R.attr.borderlessButtonStyle).apply {
                text = label; isAllCaps = false; minHeight = activity.dp(48); tag = "vpn013.routing.$key"
                setOnClickListener { for (index in selected.indices) { selected[index] = value; dialog.listView.setItemChecked(index, value) }; update() }
            }, LinearLayout.LayoutParams(0, -2, 1f))
        }
        dialog = MaterialAlertDialogBuilder(activity).setTitle("Маршрутизация · ${UnifiedAutoCoordinator.label(section)}")
            .setMultiChoiceItems(entries.map { it.title }.toTypedArray(), selected) { _, index, checked -> selected[index] = checked; update() }
            .setView(actions).setPositiveButton("Далее (0)", null).setNegativeButton("Отмена", null).create()
        dialog.setOnShowListener {
            dialog.getButton(-1).apply {
                tag = "vpn013.routing.next"
                setOnClickListener {
                    val ids = entries.filterIndexed { index, _ -> selected[index] }.map { it.id }.toSet()
                    if (ids.isNotEmpty()) { dialog.dismiss(); next(ids) }
                }
            }
            update()
        }
        dialog.show()
    }
    fun edit(activity: AppCompatActivity, initial: ApplicationRoutingStore.Selection,
             save: (ApplicationRoutingStore.Selection, () -> Unit) -> Unit) {
        var selection = initial
        var binding = false
        val manager = activity.packageManager
        val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val apps = manager.queryIntentActivities(launcher, 0).map { it.activityInfo.applicationInfo }
            .distinctBy { it.packageName }.filter { it.packageName != activity.packageName }
            .sortedBy { manager.getApplicationLabel(it).toString() }.take(200)
        val byPackage = apps.associateBy { it.packageName }
        val visible = (byPackage.keys + selection.only + selection.bypass).take(600)
        val missing = visible.filter { it !in byPackage }.sorted()
        fun name(id: String) = byPackage[id]?.let { manager.getApplicationLabel(it).toString().take(256) }
            ?: "Недоступное приложение ${missing.indexOf(id) + 1}"
        val sorted = visible.sortedBy(::name)
        val box = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL; setPadding(activity.dp(20), 0, activity.dp(20), 0) }
        box.addView(TextView(activity).apply {
            text = "Установленные приложения. Пока режимы выключены, прежние правила каждого сервера сохраняются. Сетевые исключения профиля сохраняются. VPN013 остаётся в туннеле для проверки подключения."
            textSize = 14f; setPadding(0, activity.dp(8), 0, activity.dp(12))
        })
        val only = MaterialSwitch(activity).apply { text = "VPN только для выбранных"; minHeight = activity.dp(48); tag = "vpn013.routing.apps.only" }
        val bypass = MaterialSwitch(activity).apply { text = "Выбранные без VPN"; minHeight = activity.dp(48); tag = "vpn013.routing.apps.bypass" }
        box.addView(only); box.addView(bypass)
        val search = TextInputEditText(activity).apply { maxLines = 1; tag = "vpn013.routing.apps.search" }
        box.addView(TextInputLayout(activity).apply { hint = "Найти приложение"; addView(search) })
        val rows = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
        box.addView(rows)
        fun render() {
            binding = true; only.isChecked = selection.mode == "only"; bypass.isChecked = selection.mode == "bypass"; binding = false
            rows.removeAllViews()
            val query = search.text.toString().trim()
            val filtered = sorted.filter { query.isEmpty() || name(it).contains(query, ignoreCase = true) }
            if (filtered.isEmpty()) rows.addView(TextView(activity).apply { text = "Приложения не найдены"; setPadding(0, activity.dp(16), 0, activity.dp(16)) })
            for (id in filtered) {
                val line = LinearLayout(activity).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
                byPackage[id]?.let { application ->
                    line.addView(ImageView(activity).apply { setImageDrawable(runCatching { manager.getApplicationIcon(application) }.getOrNull()); importantForAccessibility = android.view.View.IMPORTANT_FOR_ACCESSIBILITY_NO },
                        LinearLayout.LayoutParams(activity.dp(32), activity.dp(32)).apply { marginEnd = activity.dp(8) })
                }
                line.addView(MaterialCheckBox(activity).apply {
                    text = name(id); minHeight = activity.dp(52); isEnabled = selection.mode != "unchanged"
                    isChecked = id in selection.active; tag = "vpn013.routing.apps.$id"
                    setOnCheckedChangeListener { _, checked ->
                        val values = if (checked) selection.active + id else selection.active - id
                        selection = if (selection.mode == "only") selection.copy(only = values) else selection.copy(bypass = values)
                    }
                }, LinearLayout.LayoutParams(0, -2, 1f))
                rows.addView(line)
            }
        }
        only.setOnCheckedChangeListener { _, checked -> if (!binding) { selection = selection.copy(mode = if (checked) "only" else "unchanged"); render() } }
        bypass.setOnCheckedChangeListener { _, checked -> if (!binding) { selection = selection.copy(mode = if (checked) "bypass" else "unchanged"); render() } }
        search.doAfterTextChanged { render() }
        render()
        val scroll = ScrollView(activity).apply { addView(box) }
        val dialog = MaterialAlertDialogBuilder(activity).setTitle("Маршрутизация приложений").setView(scroll)
            .setPositiveButton("Сохранить", null).setNegativeButton("Отмена", null).create()
        dialog.setOnShowListener {
            dialog.getButton(-1).apply {
                tag = "vpn013.routing.apps.save"
                setOnClickListener {
                    if (selection.mode != "unchanged" && selection.active.isEmpty()) search.error = "Выберите хотя бы одно приложение"
                    else save(selection) { dialog.dismiss() }
                }
            }
        }
        dialog.show()
    }
}
