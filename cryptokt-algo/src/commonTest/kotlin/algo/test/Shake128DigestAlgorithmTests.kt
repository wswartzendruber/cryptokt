/*
 * SPDX-FileCopyrightText: 2021 William Swartzendruber <wswartzendruber@gmail.com>
 *
 * SPDX-License-Identifier: CC0-1.0
 */

package org.cryptokt.algo.test

import org.cryptokt.algo.Shake128DigestAlgorithm

class Shake128DigestAlgorithmTests : DigestAlgorithmTests() {

    val digests256 = mapOf(

        "".toByteArrayFromHex()
        to
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
    )

    override val configurations = mapOf(

        DigestAlgorithmConfiguration({ Shake128DigestAlgorithm(32) }, "SHAKE128-256")
        to
        digests256,
    )
}
