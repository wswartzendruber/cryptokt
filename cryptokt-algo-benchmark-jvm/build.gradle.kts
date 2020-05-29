/*
 * Copyright 2020 William Swartzendruber
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a
 * copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

plugins {
    kotlin("jvm")
    application
}

repositories {
    jcenter()
}

dependencies {
    implementation(project(":cryptokt-algo"))
    implementation(kotlin("stdlib-jdk8"))
    implementation("org.bouncycastle:bcprov-jdk15on:1.65")
}

application {
    mainClassName = "org.cryptokt.algo.benchmark.jvm.ApplicationKt"
}
