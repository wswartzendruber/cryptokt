/*
 * Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/
 */

plugins {
    kotlin("multiplatform").version("1.3.72").apply(false)
    kotlin("jvm").version("1.3.72").apply(false)
}

allprojects {
    repositories {
        jcenter()
    }
}
