/*
 * Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/
 */

package org.cryptokt.algo.test

import kotlin.test.assertTrue
import kotlin.test.Test

import org.cryptokt.algo.DigestAlgorithm

abstract class DigestAlgorithmTests {

    abstract val configurations: Map<DigestAlgorithmConfiguration, Map<ByteArray, String>>

    @Test
    fun accuracy() {
        for ((dac, digests) in configurations) {
            println("${dac.description}")
            dac.daf().let { da ->
                for (digest in digests) {
                    println("> ${digest.key.toHexString()}")
                    da.input(digest.key)
                    assertTrue(da.digest().toHexString() == digest.value)
                }
            }
            println()
        }
    }
}

data class DigestAlgorithmConfiguration(val daf: () -> DigestAlgorithm, val description: String)
