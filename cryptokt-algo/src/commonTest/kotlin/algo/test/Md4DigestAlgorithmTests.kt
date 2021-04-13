/*
 * Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/
 */

package org.cryptokt.algo.test

import org.cryptokt.algo.Md4DigestAlgorithm

class Md4DigestAlgorithmTests : DigestAlgorithmTests() {

    val digests = mapOf(

        "".toByteArrayFromAscii()
        to
        "31d6cfe0d16ae931b73c59d7e0c089c0",

        "a".toByteArrayFromAscii()
        to
        "bde52cb31de33e46245e05fbdbd6fb24",

        "abc".toByteArrayFromAscii()
        to
        "a448017aaf21d8525fc10ae87aa6729d",

        "message digest".toByteArrayFromAscii()
        to
        "d9130a8164549fe818874806e1c7014b",

        "abcdefghijklmnopqrstuvwxyz".toByteArrayFromAscii()
        to
        "d79e1c308aa5bbcdeea8ed63df412da9",

        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            .toByteArrayFromAscii()
        to
        "043f8582f241db351ce627e153e7f0e4",

        "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            .toByteArrayFromAscii()
        to
        "e33b4ddc9c38f2199c3e7b164fcc0536",
    )

    override val configurations = mapOf(
        DigestAlgorithmConfiguration({ Md4DigestAlgorithm() }, "MD4") to digests,
    )
}
