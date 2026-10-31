// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.view.Gravity
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.doAfterTextChanged
import com.google.android.material.button.MaterialButton
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout

/** Service list only: caller owns offline save and connection policy. */
object ServiceRoutingUI {
    private fun AppCompatActivity.dp(v: Int) = (resources.displayMetrics.density * v).toInt()
    fun edit(activity: AppCompatActivity, catalog: ServiceRoutingCatalog, initial: ServiceRoutingCatalog.Selection,
             openApps: () -> Unit, save: (ServiceRoutingCatalog.Selection, () -> Unit) -> Unit) {
        var selection = initial
        var binding = false
        val expanded = mutableSetOf<String>()
        val box = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL; setPadding(activity.dp(20), 0, activity.dp(20), 0) }
        box.addView(TextView(activity).apply { text = "Маршрутизация по адресам IPv4 из каталога. Адреса сервисов могут меняться или совпадать с адресами других сайтов. IPv6 и DNS следуют правилам профиля. Правила установленных приложений действуют совместно с правилами сервисов. Пока оба режима выключены, сохраняются прежние маршруты сервера."; textSize = 14f; setPadding(0, activity.dp(8), 0, activity.dp(12)) })
        val only = MaterialSwitch(activity).apply { text = "VPN только для выбранных сервисов"; tag = "vpn013.routing.services.only" }
        val bypass = MaterialSwitch(activity).apply { text = "Выбранные сервисы без VPN"; tag = "vpn013.routing.services.bypass" }
        box.addView(only); box.addView(bypass)
        val search = TextInputEditText(activity).apply { maxLines = 1; tag = "vpn013.routing.services.search" }
        box.addView(TextInputLayout(activity).apply { hint = "Найти сервис"; addView(search) })
        val groups = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }; box.addView(groups)
        lateinit var dialog: androidx.appcompat.app.AlertDialog
        box.addView(MaterialButton(activity, null, com.google.android.material.R.attr.borderlessButtonStyle).apply {
            text = "Установленные приложения"; isAllCaps = false; tag = "vpn013.routing.services.apps"
            setOnClickListener { dialog.dismiss(); openApps() }
        }, 0)
        fun render() {
            binding = true; only.isChecked = selection.mode == "only"; bypass.isChecked = selection.mode == "bypass"; binding = false
            groups.removeAllViews()
            val query = search.text.toString().trim()
            for (group in catalog.groups) {
                val matches = if (query.isEmpty() || group.title.contains(query, true)) group.services else group.services.filter { it.name.contains(query, true) }
                if (matches.isEmpty()) continue
                val open = group.id in expanded || query.isNotEmpty()
                groups.addView(MaterialButton(activity, null, com.google.android.material.R.attr.borderlessButtonStyle).apply {
                    text = "${if (open) "▾" else "▸"} ${group.title} (${matches.size})"; isAllCaps = false; gravity = Gravity.START or Gravity.CENTER_VERTICAL
                    tag = "vpn013.routing.services.group.${group.id}"
                    setOnClickListener { if (!expanded.add(group.id)) expanded.remove(group.id); render() }
                })
                if (!open) continue
                for (service in matches) {
                    val available = catalog.supported(service.id)
                    groups.addView(MaterialCheckBox(activity).apply {
                        text = "${service.iconText}  ${service.name}" + if (available) "" else " — пока недоступен: требуется маршрутизация по доменам"
                        minHeight = activity.dp(52); isEnabled = available && selection.mode != "unchanged"; isChecked = service.id in selection.active
                        tag = "vpn013.routing.services.${service.id}"
                        setOnCheckedChangeListener { _, checked ->
                            val values = if (checked) selection.active + service.id else selection.active - service.id
                            selection = if (selection.mode == "only") selection.copy(only = values) else selection.copy(bypass = values)
                        }
                    })
                }
            }
        }
        only.setOnCheckedChangeListener { _, checked -> if (!binding) { selection = selection.copy(mode = if (checked) "only" else "unchanged"); render() } }
        bypass.setOnCheckedChangeListener { _, checked -> if (!binding) { selection = selection.copy(mode = if (checked) "bypass" else "unchanged"); render() } }
        search.doAfterTextChanged { render() }; render()
        dialog = MaterialAlertDialogBuilder(activity).setTitle("Маршрутизация сервисов").setView(ScrollView(activity).apply { addView(box) })
            .setPositiveButton("Сохранить", null).setNegativeButton("Отмена", null).create()
        dialog.setOnShowListener { dialog.getButton(-1).apply { tag = "vpn013.routing.services.save"; setOnClickListener {
            val problem = runCatching { catalog.resolve(selection) }.exceptionOrNull()
            if (problem != null) search.error = "Выберите доступные сервисы или выключите режим"
            else save(selection) { dialog.dismiss() }
        } } }
        dialog.show()
    }
}
