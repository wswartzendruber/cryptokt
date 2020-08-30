/*
 * Copyright 2020 William Swartzendruber
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a
 * copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package org.cryptokt.algo

/**
 * Represents a hash algorithm which takes input of arbitrary length and produces a digest of
 * fixed length.
 *
 * @param[blockSize] The size in bits of each complete input block.
 * @param[digestSize] The size in bits of the digest.
 *
 * @property[blockSize] The size in bits of each complete input block.
 * @property[digestSize] The size in bits of the digest.
 */
public abstract class DigestAlgorithm(
    public val blockSize: Int,
    public val digestSize: Int,
) {

    private val blockSizeBytes = blockSize.wholeBytes()
    private val digestSizeBytes = digestSize.wholeBytes()
    private var mo = 0
    private val mb = ByteArray(blockSizeBytes)
    private val cmb = ByteArray(blockSizeBytes)

    /**
     * Inputs the specified [buffer] segment, starting at the zero-based [offset], up to and
     * including [length] bytes from there.
     */
    public fun input(
        buffer: ByteArray,
        offset: Int = 0,
        length: Int = buffer.size,
    ): Unit {
        mo = forEachSegment(
            mb, mo,
            buffer, offset, length,
            {
                transformBlock(mb)
            }
        )
    }

    /**
     * Writes the digest of the message into the specified [output] buffer, starting at the
     * zero-based [offset], and then returning the [output]. The hash algorithm's internal state
     * will then be reset and the instance will be ready for re-use with the same arguments it
     * was initialized with.
     */
    public fun digest(
        output: ByteArray = ByteArray(digestSizeBytes),
        offset: Int = 0,
    ): ByteArray {

        if (digestSizeBytes + offset > output.size)
            throw IllegalArgumentException("Output buffer too small for the given offset.")

        transformFinal(output, offset, mb, mo)
        reset()

        return output
    }

    /**
     * Resets the internal state of the hash algorithm, preserving any configuration parameters.
     */
    public fun reset(): Unit {
        mo = 0
        cmb.copyInto(mb)
        resetState()
    }

    /**
     * Invoked in order to input a single [block] of input data. The size of the [block] will
     * always be [blockSize] rounded up to a whole-byte value.
     */
    protected abstract fun transformBlock(block: ByteArray): Unit

    /**
     * Invoked in order to calculate the final message digest and place it into an [output]
     * buffer.
     *
     * @param[offset] The starting location in the [output] buffer to write the digest.
     * @param[remaining] Any remaining input data not previously processed by [transformBlock].
     *     Its size will always be [blockSize] rounded up to a whole-byte value.
     * @param[remainingSize] The number of bytes that are [remaining].
     */
    protected abstract fun transformFinal(
        output: ByteArray,
        offset: Int = 0,
        remaining: ByteArray,
        remainingSize: Int,
    ): Unit

    /**
     * Invoked in order to reset the implementation-dependent state of the hash algorithm. Any
     * arguments passed in during initialization should still be honored.
     */
    protected abstract fun resetState(): Unit
}
