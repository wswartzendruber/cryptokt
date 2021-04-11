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

public class Sha3DigestAlgorithm(
    private val size: Sha3DigestSize = Sha3DigestSize._224
) : KeccakDigestAlgorithm(size.capacity, 28) {

    protected override fun transformFinal(
        output: ByteArray,
        offset: Int,
        remaining: ByteArray,
        remainingSize: Int,
    ): Unit {

        // if (remainingSize > 55) {
        //     padding.copyInto(remaining, remainingSize, 0, 64 - remainingSize)
        //     transformBlock(remaining)
        //     padding.copyInto(remaining, 0, 8, 64)
        // } else {
        //     padding.copyInto(remaining, remainingSize, 0, 56 - remainingSize)
        // }

        // lms.copyIntoBe(remaining, 56)

        // transformBlock(remaining)

        // for (i in 0 until 5)
        //     r[i].copyIntoBe(output, offset + 4 * i)
    }
}
