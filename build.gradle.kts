/*
 * SPDX-FileCopyrightText: 2021 William Swartzendruber <wswartzendruber@gmail.com>
 *
 * SPDX-License-Identifier: CC0-1.0
 */

plugins {
    kotlin("multiplatform").version("1.5.0").apply(false)
    kotlin("jvm").version("1.5.0").apply(false)
    id("org.jetbrains.dokka").version("1.4.20").apply(false)
}

allprojects {
    repositories {
        mavenCentral()
    }
}
