/*
 * SPDX-FileCopyrightText: 2021 William Swartzendruber <wswartzendruber@gmail.com>
 *
 * SPDX-License-Identifier: CC0-1.0
 */

plugins {
    kotlin("jvm")
    application
}

dependencies {
    implementation(project(":cryptokt-algo"))
    implementation("org.bouncycastle:bcprov-jdk15on:1.65")
}

application {
    mainClass.set("org.cryptokt.algo.benchmark.jvm.ApplicationKt")
}
