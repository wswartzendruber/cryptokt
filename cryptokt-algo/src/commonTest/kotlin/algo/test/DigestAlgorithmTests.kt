/*
 * Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/
 */

package org.cryptokt.algo.test

import kotlin.test.assertTrue
import kotlin.test.Test

import org.cryptokt.algo.DigestAlgorithm

abstract class DigestAlgorithmTests {

    abstract val digests: Map<ByteArray, String>

    abstract fun newDigestAlgorithm(): DigestAlgorithm

    @Test
    fun accuracy() {
        newDigestAlgorithm().let { da ->
            for (digest in digests) {
                da.input(digest.key)
                assertTrue(da.digest().toHexString() == digest.value)
            }
        }
    }
}
