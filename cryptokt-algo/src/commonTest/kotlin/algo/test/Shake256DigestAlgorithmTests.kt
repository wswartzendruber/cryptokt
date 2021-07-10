/*
 * SPDX-FileCopyrightText: 2021 William Swartzendruber <wswartzendruber@gmail.com>
 *
 * SPDX-License-Identifier: CC0-1.0
 */

package org.cryptokt.algo.test

import org.cryptokt.algo.Shake256DigestAlgorithm

class Shake256DigestAlgorithmTests : DigestAlgorithmTests() {

    val digests512 = mapOf(

        "".toByteArrayFromHex()
        to
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05" +
            "019d67b592f6fc821c49479ab48640292eacb3b7c4be",
    )

    override val configurations = mapOf(

        DigestAlgorithmConfiguration({ Shake256DigestAlgorithm(64) }, "SHAKE256-512")
        to
        digests512,
    )
}
