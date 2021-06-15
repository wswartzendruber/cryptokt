/*
 * SPDX-FileCopyrightText: 2021 William Swartzendruber <wswartzendruber@gmail.com>
 *
 * SPDX-License-Identifier: CC0-1.0
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
    commonTestImplementation(kotlin("test"))
    // JVM
    "jvmTestImplementation"("commons-codec:commons-codec:1.15")
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
