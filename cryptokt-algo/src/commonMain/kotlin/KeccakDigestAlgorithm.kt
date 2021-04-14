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

import kotlin.experimental.or
import kotlin.experimental.xor
import kotlin.math.min

/**
 * The Keccak[c] function, implemented here as an abstract [DigestAlgorithm] class. This serves
 * as the basis for the SHA-3 suite of hash algorithms and also the SHAKE128 and SHAKE256
 * extendable output functions. The block and digest sizes vary.
 *
 * @param[capacity] The capacity in bytes of the Keccak sponge function. See FIPS-202 Section 4
 *     for more information.
 * @param[digestSize] The size in bytes of the digest.
 * @param[paddingSingle] The byte value to use should a single padding byte be needed. See
 *     FIPS-202 Appendix B.2 for more information.
 * @param[paddingStart] The starting byte value to use should multiple padding bytes be needed.
 *     See FIPS-202 Appendix B.2 for more information.
 * @param[paddingEnd] The ending byte value to use should multiple padding bytes be needed. See
 *     FIPS-202 Appendix B.2 for more information.
 */
public abstract class KeccakDigestAlgorithm(
    capacity: Int,
    digestSize: Int,
    private val paddingSingle: Byte,
    private val paddingStart: Byte,
    private val paddingEnd: Byte,
) : DigestAlgorithm(200 - capacity, digestSize) {

    private val a = LongArray(25)
    private val p = ByteArray(200)
    private val s = ByteArray(200)

    protected override fun transformBlock(block: ByteArray): Unit {
        block.copyInto(p)
        for (i in 0 until 200)
            s[i] = s[i] xor p[i]
        permutate()
    }

    protected override fun transformFinal(
        output: ByteArray,
        offset: Int,
        remaining: ByteArray,
        remainingSize: Int,
    ): Unit {

        val left = blockSize - remainingSize

        when {
            left == 1 -> {
                remaining[blockSize - 1] = paddingSingle
            }
            left >= 2 -> {
                remaining[remainingSize] = paddingStart
                for (i in (remainingSize + 1) until (blockSize - 1))
                    remaining[i] = 0
                remaining[blockSize - 1] = paddingEnd
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
            s.copyInto(output, index + offset, 0, increment)
            index += increment
            if (index < digestSize)
                permutate()
        }
    }

    protected override fun resetState(): Unit {
        cl.copyInto(a)
        cb.copyInto(p)
        cb.copyInto(s)
    }

    private fun permutate() {

        bytesToLanes()

        var t0 = a[0]
        var t1 = a[1]
        var t2 = a[2]
        var t3 = a[3]
        var t4 = a[4]
        var t5 = a[5]
        var t6 = a[6]
        var t7 = a[7]
        var t8 = a[8]
        var t9 = a[9]
        var t10 = a[10]
        var t11 = a[11]
        var t12 = a[12]
        var t13 = a[13]
        var t14 = a[14]
        var t15 = a[15]
        var t16 = a[16]
        var t17 = a[17]
        var t18 = a[18]
        var t19 = a[19]
        var t20 = a[20]
        var t21 = a[21]
        var t22 = a[22]
        var t23 = a[23]
        var t24 = a[24]
        var t25: Long
        var t26: Long
        var t27: Long
        var t28: Long
        var t29: Long
        var t30: Long
        var t31: Long
        var t32: Long
        var t33: Long
        var t34: Long
        var t35: Long
        var t36: Long
        var t37: Long
        var t38: Long
        var t39: Long
        var t40: Long
        var t41: Long
        var t42: Long
        var t43: Long
        var t44: Long
        var t45: Long
        var t46: Long
        var t47: Long
        var t48: Long
        var t49: Long
        var t50: Long
        var t51: Long
        var t52: Long
        var t53: Long
        var t54: Long
        var t55: Long
        var t56: Long
        var t57: Long
        var t58: Long
        var t59: Long

        for(r in 0 until 24 step 2)
        {
            t25 = t0 xor t5 xor t10 xor t15 xor t20
            t26 = t1 xor t6 xor t11 xor t16 xor t21
            t27 = t2 xor t7 xor t12 xor t17 xor t22
            t28 = t3 xor t8 xor t13 xor t18 xor t23
            t29 = t4 xor t9 xor t14 xor t19 xor t24

            t30 = t29 xor (t26 rl 1)
            t31 = t25 xor (t27 rl 1)
            t32 = t26 xor (t28 rl 1)
            t33 = t27 xor (t29 rl 1)
            t34 = t28 xor (t25 rl 1)

            t0 = t0 xor t30
            t25 = t0
            t6 = t6 xor t31
            t26 = t6 rl 44
            t12 = t12 xor t32
            t27 = t12 rl 43
            t18 = t18 xor t33
            t28 = t18 rl 21
            t24 = t24 xor t34
            t29 = t24 rl 14
            t35 = t25 xor (t26.inv() and t27)
            t35 = t35 xor roundConstants[r]
            t36 = t26 xor (t27.inv() and t28)
            t37 = t27 xor (t28.inv() and t29)
            t38 = t28 xor (t29.inv() and t25)
            t39 = t29 xor (t25.inv() and t26)

            t3 = t3 xor t33
            t25 = t3 rl 28
            t9 = t9 xor t34
            t26 = t9 rl 20
            t10 = t10 xor t30
            t27 = t10 rl 3
            t16 = t16 xor t31
            t28 = t16 rl 45
            t22 = t22 xor t32
            t29 = t22 rl 61
            t40 = t25 xor (t26.inv() and t27)
            t41 = t26 xor (t27.inv() and t28)
            t42 = t27 xor (t28.inv() and t29)
            t43 = t28 xor (t29.inv() and t25)
            t44 = t29 xor (t25.inv() and t26)

            t1 = t1 xor t31
            t25 = t1 rl 1
            t7 = t7 xor t32
            t26 = t7 rl 6
            t13 = t13 xor t33
            t27 = t13 rl 25
            t19 = t19 xor t34
            t28 = t19 rl  8
            t20 = t20 xor t30
            t29 = t20 rl 18
            t45 = t25 xor (t26.inv() and t27)
            t46 = t26 xor (t27.inv() and t28)
            t47 = t27 xor (t28.inv() and t29)
            t48 = t28 xor (t29.inv() and t25)
            t49 = t29 xor (t25.inv() and t26)

            t4 = t4 xor t34
            t25 = t4 rl 27
            t5 = t5 xor t30
            t26 = t5 rl 36
            t11 = t11 xor t31
            t27 = t11 rl 10
            t17 = t17 xor t32
            t28 = t17 rl 15
            t23 = t23 xor t33
            t29 = t23 rl 56
            t50 = t25 xor (t26.inv() and t27)
            t51 = t26 xor (t27.inv() and t28)
            t52 = t27 xor (t28.inv() and t29)
            t53 = t28 xor (t29.inv() and t25)
            t54 = t29 xor (t25.inv() and t26)

            t2 = t2 xor t32
            t25 = t2 rl 62
            t8 = t8 xor t33
            t26 = t8 rl 55
            t14 = t14 xor t34
            t27 = t14 rl 39
            t15 = t15 xor t30
            t28 = t15 rl 41
            t21 = t21 xor t31
            t29 = t21 rl 2
            t55 = t25 xor (t26.inv() and t27)
            t56 = t26 xor (t27.inv() and t28)
            t57 = t27 xor (t28.inv() and t29)
            t58 = t28 xor (t29.inv() and t25)
            t59 = t29 xor (t25.inv() and t26)

            t25 = t35 xor t40 xor t45 xor t50 xor t55
            t26 = t36 xor t41 xor t46 xor t51 xor t56
            t27 = t37 xor t42 xor t47 xor t52 xor t57
            t28 = t38 xor t43 xor t48 xor t53 xor t58
            t29 = t39 xor t44 xor t49 xor t54 xor t59

            t30 = t29 xor (t26 rl 1)
            t31 = t25 xor (t27 rl 1)
            t32 = t26 xor (t28 rl 1)
            t33 = t27 xor (t29 rl 1)
            t34 = t28 xor (t25 rl 1)

            t35 = t35 xor t30
            t25 = t35
            t41 = t41 xor t31
            t26 = t41 rl 44
            t47 = t47 xor t32
            t27 = t47 rl 43
            t53 = t53 xor t33
            t28 = t53 rl 21
            t59 = t59 xor t34
            t29 = t59 rl 14
            t0 = t25 xor (t26.inv() and t27)
            t0 = t0 xor roundConstants[r + 1]
            t1 = t26 xor (t27.inv() and t28)
            t2 = t27 xor (t28.inv() and t29)
            t3 = t28 xor (t29.inv() and t25)
            t4 = t29 xor (t25.inv() and t26)

            t38 = t38 xor t33
            t25 = t38 rl 28
            t44 = t44 xor t34
            t26 = t44 rl 20
            t45 = t45 xor t30
            t27 = t45 rl 3
            t51 = t51 xor t31
            t28 = t51 rl 45
            t57 = t57 xor t32
            t29 = t57 rl 61
            t5 = t25 xor (t26.inv() and t27)
            t6 = t26 xor (t27.inv() and t28)
            t7 = t27 xor (t28.inv() and t29)
            t8 = t28 xor (t29.inv() and t25)
            t9 = t29 xor (t25.inv() and t26)

            t36 = t36 xor t31
            t25 = t36 rl 1
            t42 = t42 xor t32
            t26 = t42 rl 6
            t48 = t48 xor t33
            t27 = t48 rl 25
            t54 = t54 xor t34
            t28 = t54 rl 8
            t55 = t55 xor t30
            t29 = t55 rl 18
            t10 = t25 xor (t26.inv() and t27)
            t11 = t26 xor (t27.inv() and t28)
            t12 = t27 xor (t28.inv() and t29)
            t13 = t28 xor (t29.inv() and t25)
            t14 = t29 xor (t25.inv() and t26)

            t39 = t39 xor t34
            t25 = t39 rl 27
            t40 = t40 xor t30
            t26 = t40 rl 36
            t46 = t46 xor t31
            t27 = t46 rl 10
            t52 = t52 xor t32
            t28 = t52 rl 15
            t58 = t58 xor t33
            t29 = t58 rl 56
            t15 = t25 xor (t26.inv() and t27)
            t16 = t26 xor (t27.inv() and t28)
            t17 = t27 xor (t28.inv() and t29)
            t18 = t28 xor (t29.inv() and t25)
            t19 = t29 xor (t25.inv() and t26)

            t37 = t37 xor t32
            t25 = t37 rl 62
            t43 = t43 xor t33
            t26 = t43 rl 55
            t49 = t49 xor t34
            t27 = t49 rl 39
            t50 = t50 xor t30
            t28 = t50 rl 41
            t56 = t56 xor t31
            t29 = t56 rl 2
            t20 = t25 xor (t26.inv() and t27)
            t21 = t26 xor (t27.inv() and t28)
            t22 = t27 xor (t28.inv() and t29)
            t23 = t28 xor (t29.inv() and t25)
            t24 = t29 xor (t25.inv() and t26)
        }

        a[0] = t0
        a[1] = t1
        a[2] = t2
        a[3] = t3
        a[4] = t4
        a[5] = t5
        a[6] = t6
        a[7] = t7
        a[8] = t8
        a[9] = t9
        a[10] = t10
        a[11] = t11
        a[12] = t12
        a[13] = t13
        a[14] = t14
        a[15] = t15
        a[16] = t16
        a[17] = t17
        a[18] = t18
        a[19] = t19
        a[20] = t20
        a[21] = t21
        a[22] = t22
        a[23] = t23
        a[24] = t24

        lanesToBytes()
    }

    private fun bytesToLanes() {
        for (i in 0 until 25) {
            a[i] = 0
            for (j in 0 until 8)
                a[i] = a[i] or (s[i * 8 + j].toLong() and 255 shl (8 * j))
        }
    }

    private fun lanesToBytes() {
        for (i in 0 until 25) {
            for (j in 0 until 8)
                s[i * 8 + j] = ((a[i] ushr (8 * j)) and 255).toByte()
        }
    }

    private companion object {

        private val cb = ByteArray(200)
        private val cl = LongArray(25)
        private val roundConstants = longArrayOf(
            1, 32898, -9223372036854742902, -9223372034707259392, 32907, 2147483649,
            -9223372034707259263, -9223372036854743031, 138, 136, 2147516425, 2147483658,
            2147516555, -9223372036854775669, -9223372036854742903, -9223372036854743037,
            -9223372036854743038, -9223372036854775680, 32778, -9223372034707292150,
            -9223372034707259263, -9223372036854742912, 2147483649, -9223372034707259384,
        )
    }
}
