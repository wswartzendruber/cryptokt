/*
 * SPDX-FileCopyrightText: 2021 William Swartzendruber <wswartzendruber@gmail.com>
 *
 * SPDX-License-Identifier: CC0-1.0
 */

package org.cryptokt.algo.test

import org.cryptokt.algo.Md2DigestAlgorithm

class Md2DigestAlgorithmTests : DigestAlgorithmTests() {

    val digests = mapOf(

        "".toByteArrayFromAscii()
        to
        "8350e5a3e24c153df2275c9f80692773",

        "a".toByteArrayFromAscii()
        to
        "32ec01ec4a6dac72c0ab96fb34c0b5d1",

        "abc".toByteArrayFromAscii()
        to
        "da853b0d3f88d99b30283a69e6ded6bb",

        "message digest".toByteArrayFromAscii()
        to
        "ab4f496bfb2a530b219ff33031fe06b0",

        "abcdefghijklmnopqrstuvwxyz".toByteArrayFromAscii()
        to
        "4e8ddff3650292ab5a4108c3aa47940b",

        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toByteArrayFromAscii()
        to
        "da33def2a42df13975352846c30338cd",

        "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            .toByteArrayFromAscii()
        to
        "d5976f79d83d3a0dc9806c3c66f3efd8",
    )

    override val configurations = mapOf(
        DigestAlgorithmConfiguration({ Md2DigestAlgorithm() }, "MD2") to digests,
    )
}
