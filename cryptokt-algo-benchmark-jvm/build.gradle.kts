/*
 * Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/
 */

plugins {
    kotlin("jvm")
    application
}

dependencies {
    implementation(platform(kotlin("bom")))
    implementation(project(":cryptokt-algo"))
    implementation("org.bouncycastle:bcprov-jdk15on:1.65")
}

application {
    mainClassName = "org.cryptokt.algo.benchmark.jvm.ApplicationKt"
}
