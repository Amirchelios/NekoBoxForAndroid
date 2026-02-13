package io.nekohasekai.sagernet.bg.proto

import io.nekohasekai.sagernet.BuildConfig
import io.nekohasekai.sagernet.bg.GuardedProcessPool
import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.fmt.buildConfig
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.suspendCancellableCoroutine
import libcore.Libcore
import moe.matsuri.nb4a.net.LocalResolverImpl

class TestInstance(profile: ProxyEntity, val link: String, private val timeout: Int) :
    BoxInstance(profile) {

    suspend fun doTest(): Int {
        return suspendCancellableCoroutine { c ->
            processes = GuardedProcessPool {
                Logs.w(it)
                if (c.isActive) c.resumeWith(Result.failure(it))
            }
            c.invokeOnCancellation {
                runCatching { close() }
            }
            runOnDefaultDispatcher {
                use {
                    try {
                        init()
                        launch()
                        if (processes.processCount > 0) {
                            // wait for plugin start
                            delay(500)
                        }
                        if (c.isActive) c.resumeWith(Result.success(Libcore.urlTest(box, link, timeout)))
                    } catch (e: Exception) {
                        if (c.isActive) c.resumeWith(Result.failure(e))
                    }
                }
            }
        }
    }

    override fun buildConfig() {
        config = buildConfig(profile, true)
    }

    override suspend fun loadConfig() {
        // don't call destroyAllJsi here
        if (BuildConfig.DEBUG) Logs.d(config.config)
        box = Libcore.newSingBoxInstance(config.config, LocalResolverImpl)
    }

}
