// Top-level build file where you can add configuration options common to all sub-projects/modules.
allprojects {
}

tasks.register<Delete>("clean") {
    delete(rootProject.buildDir)
}

plugins {
    id("com.google.devtools.ksp") version "2.0.21-1.0.27" apply false
}
