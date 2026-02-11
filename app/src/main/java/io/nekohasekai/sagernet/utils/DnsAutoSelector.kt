package io.nekohasekai.sagernet.utils

import io.nekohasekai.sagernet.ktx.Logs
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import kotlin.math.min

object DnsAutoSelector {

    data class Provider(
        val name: String,
        val primary: String,
        val secondary: String? = null,
    )

    private const val TIMEOUT_MS = 1200
    private const val MAX_CONCURRENCY = 16

    val providers = listOf(
        Provider("Shecan", "178.22.122.100", "185.51.200.2"),
        Provider("Google", "8.8.8.8", "8.8.4.4"),
        Provider("Quad9", "9.9.9.9", "149.112.112.112"),
        Provider("Cloudflare", "1.1.1.1", "1.0.0.1"),
        Provider("AdGuard DNS", "94.140.14.14", "94.140.15.15"),
        Provider("Control D", "76.76.2.0", "76.76.10.0"),
        Provider("OpenDNS Home", "208.67.222.222", "208.67.220.220"),
        Provider("CleanBrowsing", "185.228.168.9", "185.228.169.9"),
        Provider("DNS.WATCH", "84.200.69.80", "84.200.70.40"),
        Provider("Comodo Secure DNS", "8.26.56.26", "8.20.247.20"),
        Provider("CenturyLink (Level3)", "205.171.3.66", "205.171.202.166"),
        Provider("CIRA Canadian Shield", "149.112.121.10", "149.112.122.10"),
        Provider("OpenNIC", "138.197.140.189", "137.220.55.93"),
        Provider("Dyn", "216.146.35.35", "216.146.36.36"),
        Provider("Yandex DNS", "77.88.8.8", "77.88.8.1"),
        Provider("Hurricane Electric", "74.82.42.42"),
        Provider("UltraDNS", "64.6.64.6", "64.6.65.6"),
        Provider("DNS for Family", "94.130.180.225", "78.47.64.161"),
        Provider("FlashStart", "185.236.104.104", "185.236.105.105"),
        Provider("Freenom World", "80.80.80.80", "80.80.81.81"),
    )

    suspend fun selectBest(): Provider? = coroutineScope {
        val semaphore = Semaphore(MAX_CONCURRENCY)
        val results = providers.map { provider ->
            async {
                semaphore.withPermit {
                    val primary = testServer(provider.primary)
                    val secondary = provider.secondary?.let { testServer(it) }
                    val best = listOfNotNull(primary, secondary).minOrNull() ?: return@withPermit null
                    provider to best
                }
            }
        }.awaitAll().filterNotNull()

        results.minByOrNull { it.second }?.first
    }

    private fun testServer(server: String): Int? {
        return try {
            val address = InetAddress.getByName(server)
            val query = buildQuery()
            val packet = DatagramPacket(query, query.size, address, 53)
            val buf = ByteArray(512)
            val resp = DatagramPacket(buf, buf.size)
            DatagramSocket().use { socket ->
                socket.soTimeout = TIMEOUT_MS
                val start = System.nanoTime()
                socket.send(packet)
                socket.receive(resp)
                val elapsed = ((System.nanoTime() - start) / 1_000_000).toInt()
                if (elapsed <= 0) 1 else elapsed
            }
        } catch (e: Exception) {
            Logs.w(e)
            null
        }
    }

    private fun buildQuery(): ByteArray {
        // Minimal DNS query for example.com A record
        val header = byteArrayOf(
            0x12, 0x34, // ID
            0x01, 0x00, // flags: standard query
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00  // ARCOUNT
        )
        val name = byteArrayOf(
            0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
            0x00
        )
        val qtypeQclass = byteArrayOf(
            0x00, 0x01, // QTYPE A
            0x00, 0x01  // QCLASS IN
        )
        return header + name + qtypeQclass
    }
}
