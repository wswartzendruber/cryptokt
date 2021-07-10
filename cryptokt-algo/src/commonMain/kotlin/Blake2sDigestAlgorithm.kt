/*
 * SPDX-FileCopyrightText: 2021 William Swartzendruber <wswartzendruber@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.cryptokt.algo

import kotlin.experimental.xor

/**
 * The BLAKE2s digest algorithm.
 */
public class Blake2sDigestAlgorithm(digestSize: Int = 64) : DigestAlgorithm(16, digestSize) {

    protected override fun transformBlock(block: ByteArray): Unit {
    }

    protected override fun transformFinal(
        output: ByteArray,
        offset: Int,
        remaining: ByteArray,
        remainingSize: Int,
    ): Unit {
    }

    protected override fun resetState(): Unit {
    }

    private companion object {
    }
}
