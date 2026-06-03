package io.nekohasekai.sagernet.bg

import android.app.Service
import android.content.Context
import android.widget.Toast
import io.nekohasekai.sagernet.BootReceiver
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.bg.Executable
import io.nekohasekai.sagernet.bg.proto.ProxyInstance
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.GroupManager
import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.readableMessage
import io.nekohasekai.sagernet.plugin.PluginManager
import io.nekohasekai.sagernet.bg.GuardedProcessPool
import java.net.UnknownHostException
import kotlinx.coroutines.CancellationException

class BaseServiceStartController(
    private val service: BaseService.Interface,
    private val data: BaseService.Data,
) {
    suspend fun start(profile: ProxyEntity) {
        val proxy = ProxyInstance(profile, service)
        data.proxy = proxy
        BootReceiver.enabled = DataStore.persistAcrossReboot
        data.registerCloseReceiver(service as Service)
        data.changeState(BaseService.State.Connecting)
        try {
            data.notification = service.createNotification(
                io.nekohasekai.sagernet.bg.ServiceNotification.genTitle(profile)
            )
            Executable.killAll() // clean up old processes
            service.preInit()
            proxy.init()
            DataStore.currentProfile = profile.id
            proxy.processes = GuardedProcessPool {
                Logs.w(it)
                service.stopRunner(false, it.readableMessage)
            }
            service.startProcesses()
            data.changeState(BaseService.State.Connected)
            if (GroupManager.isAutoSelectAggregate(profile)) {
                service.startSmartSwitch(profile)
            }
            service.lateInit()
        } catch (_: CancellationException) {
        } catch (_: UnknownHostException) {
            service.stopRunner(false, (service as Context).getString(R.string.invalid_server))
        } catch (e: PluginManager.PluginNotFoundException) {
            Toast.makeText(service as Context, e.readableMessage, Toast.LENGTH_SHORT).show()
            Logs.w(e)
            data.binder.missingPlugin(e.plugin)
            service.stopRunner(false, null)
        } catch (exc: Throwable) {
            if (exc.javaClass.name.endsWith("proxyerror")) {
                Logs.w(exc.readableMessage)
            } else {
                Logs.w(exc)
            }
            service.stopRunner(false, "${(service as Context).getString(R.string.service_failed)}: ${exc.readableMessage}")
        } finally {
            data.connectingJob = null
        }
    }
}
