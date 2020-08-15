/*
 * Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/
 */

import org.jetbrains.dokka.gradle.DokkaTask

val group: String by project
val version: String by project

plugins {
    kotlin("multiplatform")
    id("org.jetbrains.dokka").version("1.4.0-rc")
    id("maven-publish")
}

repositories {
    jcenter()
}

kotlin {
    jvm()
}

dependencies {
    // COMMON
    commonTestImplementation(kotlin("test-common"))
    commonTestImplementation(kotlin("test-annotations-common"))
    // JVM
    "jvmTestImplementation"(kotlin("test-junit"))
}

tasks {
    dokkaHtml {
        dokkaSourceSets {
            register("commonMain") {
                displayName = "Common"
                platform = "common"
            }
            register("jvmMain") {
                displayName = "JVM"
                platform = "jvm"
            }
        }
    }
}
