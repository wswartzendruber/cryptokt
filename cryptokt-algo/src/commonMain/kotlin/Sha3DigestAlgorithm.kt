/*
 * Copyright 2021 William Swartzendruber
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */

package org.cryptokt.algo

import kotlin.math.min

public class Sha3DigestAlgorithm(
    private val size: Sha3DigestSize = Sha3DigestSize._224
) : KeccakDigestAlgorithm(size.capacity, size.digestSize) {

    protected override fun transformFinal(
        output: ByteArray,
        offset: Int,
        remaining: ByteArray,
        remainingSize: Int,
    ): Unit {

        val left = blockSize - remainingSize

        when {
            left == 1 -> {
                remaining[blockSize - 1] = -122
            }
            left >= 2 -> {
                remaining[remainingSize] = 6
                for (i in (remainingSize + 1) until (blockSize - 1))
                    remaining[i] = 0
                remaining[blockSize - 1] = -128
            }
            else -> {
                throw IllegalStateException("Remaining input block is in an invalid state.")
            }
        }

        transformBlock(remaining)

        var index = 0
        var increment: Int

        while (index < digestSize) {
            increment = min(blockSize, digestSize - index)
            state.copyInto(output, index + offset, 0, increment)
            index += increment
            if (index < digestSize)
                permutate()
        }
    }
}
