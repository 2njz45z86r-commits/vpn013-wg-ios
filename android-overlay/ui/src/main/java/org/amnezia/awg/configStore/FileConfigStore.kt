// SPDX-License-Identifier: Apache-2.0
package org.amnezia.awg.configStore
import android.content.Context
import org.amnezia.awg.config.Config
import org.amnezia.awg.r013.ProfileRegistry
/** Authenticated atomic R013 storage, isolated by application ID. */
class FileConfigStore(context: Context) : ConfigStore {
    private val registry = ProfileRegistry.get(context)
    override fun create(name: String, config: Config): Config { registry.create(name, config); return config }
    override fun delete(name: String) = registry.delete(name)
    override fun enumerate(): Set<String> = registry.names()
    override fun load(name: String): Config = registry.config(name)
    override fun rename(name: String, replacement: String) = registry.rename(name, replacement)
    override fun save(name: String, config: Config): Config { registry.save(name, config); return config }
}
