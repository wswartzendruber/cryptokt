/*
 * Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/
 */

plugins {
    kotlin("multiplatform").version("1.4.20").apply(false)
    kotlin("jvm").version("1.4.20").apply(false)
    id("org.jetbrains.dokka").version("1.4.20").apply(false)
}

allprojects {
    repositories {
        jcenter()
    }
}
