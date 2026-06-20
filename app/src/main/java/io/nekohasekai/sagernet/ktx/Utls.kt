package io.nekohasekai.sagernet.ktx

private val utlsFingerprintAliases = mapOf(
    "qq" to "chrome",
    "QQ" to "chrome",
    "chrome" to "chrome",
    "chromium" to "chrome",
    "edge" to "chrome",
    "safari" to "safari",
    "firefox" to "firefox",
    "ios" to "ios",
    "android" to "android",
    "random" to "random",
    "direct" to "direct",
    "firefox_android" to "firefox",
    "firefoxandroid" to "firefox",
    "ios_mobile" to "ios",
    "iosmobile" to "ios",
)

fun String?.normalizeUtlsFingerprint(defaultValue: String = "chrome"): String? {
    val value = this?.trim().orEmpty()
    if (value.isBlank()) return null
    return utlsFingerprintAliases[value] ?: utlsFingerprintAliases[value.lowercase()] ?: defaultValue
}
