import org.gradle.api.initialization.resolve.RepositoriesMode

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        maven(url = "https://maven.aliyun.com/repository/google") {
            content {
                includeGroupByRegex("androidx\\..*")
                includeGroup("com.android")
                includeGroupByRegex("com\\.android\\..*")
                includeGroupByRegex("com\\.google\\..*")
            }
        }
        maven(url = "https://dl.google.com/dl/android/maven2")
        mavenCentral()
        gradlePluginPortal()
        maven(url = "https://jitpack.io")
    }
}

include(":app")
rootProject.name = "NB4A"
