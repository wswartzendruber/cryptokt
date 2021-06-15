/*
 * SPDX-FileCopyrightText: 2021 William Swartzendruber <wswartzendruber@gmail.com>
 *
 * SPDX-License-Identifier: CC0-1.0
 */

package org.cryptokt.algo.test

import org.cryptokt.algo.Ripemd160DigestAlgorithm

class Ripemd160DigestAlgorithmTests : DigestAlgorithmTests() {

    val digests = mapOf(

        "".toByteArrayFromAscii()
        to
        "9c1185a5c5e9fc54612808977ee8f548b2258d31",

        "a".toByteArrayFromAscii()
        to
        "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",

        "abc".toByteArrayFromAscii()
        to
        "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",

        "message digest".toByteArrayFromAscii()
        to
        "5d0689ef49d2fae572b881b123a85ffa21595f36",

        "abcdefghijklmnopqrstuvwxyz".toByteArrayFromAscii()
        to
        "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",

        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".toByteArrayFromAscii()
        to
        "12a053384a9c0c88e405a06c27dcf49ada62eb2b",

        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toByteArrayFromAscii()
        to
        "b0e20b6e3116640286ed3a87a5713079b21f5189",

        "1234567890".repeat(8).toByteArrayFromAscii()
        to
        "9b752e45573d4b39f4dbd3323cab82bf63326bfb",

        "a".repeat(1000000).toByteArrayFromAscii()
        to
        "52783243c1697bdbe16d37f97f68f08325dc1528",
    )

    override val configurations = mapOf(
        DigestAlgorithmConfiguration({ Ripemd160DigestAlgorithm() }, "RIPEMD-160") to digests,
    )
}
