repositories {
    maven(url = "https://maven.aliyun.com/repository/google") {
        content {
            includeGroupByRegex("androidx\\..*")
            includeGroup("com.android")
            includeGroupByRegex("com\\.android\\..*")
            includeGroupByRegex("com\\.google\\..*")
        }
    }
    google()
    mavenCentral()
    gradlePluginPortal()
    maven(url = "https://jitpack.io")
}
