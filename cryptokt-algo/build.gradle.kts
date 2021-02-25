/*
 * Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/
 */

import org.jetbrains.dokka.Platform

val group: String by project
val version: String by project

plugins {
    kotlin("multiplatform")
    id("org.jetbrains.dokka")
    id("maven-publish")
}

kotlin {
    explicitApi()
    jvm { }
    js {
        browser {
            testTask {
                enabled = false
            }
        }
        nodejs { }
    }
}

dependencies {
    // Common
    commonMainImplementation(platform(kotlin("bom")))
    commonTestImplementation(kotlin("test-common"))
    commonTestImplementation(kotlin("test-annotations-common"))
    // JVM
    "jvmTestImplementation"(kotlin("test-junit"))
    "jvmTestImplementation"("commons-codec:commons-codec:1.15")
    // JS
    "jsTestImplementation"(kotlin("test-js"))
}

tasks {
    dokkaHtml {
        dokkaSourceSets {
            named("commonMain") {
                displayName.set("Common")
                platform.set(Platform.common)
            }
        }
    }
}
