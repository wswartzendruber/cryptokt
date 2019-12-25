/*
 * Copyright 2019 William Swartzendruber
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 * BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package org.cryptokt.algo

/**
 * Represents a hash algorithm which takes input of an arbitrary length and produces a digest of
 * a fixed length.
 */
public abstract class HashAlgorithm {

    /**
     * Updates the internal state of the hash algorithm by inputting the specified [buffer].
     */
    public fun input(buffer: ByteArray) = input(buffer, 0, buffer.size)

    /**
     * Updates the internal state of the hash algorithm by inputting the specified [buffer]
     * segment, starting at the zero-based [offset] up to and including [length] bytes from
     * there.
     */
    public abstract fun input(buffer: ByteArray, offset: Int, length: Int)

    /**
     * Returns the digest for the message that has been input.
     */
    public fun digest(): ByteArray = digest(ByteArray(length), 0)

    /**
     * Writes the digest for the message into the specified buffer and then returns it.
     */
    public abstract fun digest(output: ByteArray, offset: Int): ByteArray

    /**
     * Resets the internal state of the hash algorithm.
     */
    public abstract fun reset()

    /**
     * Returns the length in whole bytes of the digest.
     */
    public abstract val length: Int

    /**
     * Returns the length in bits of the digest.
     */
    public abstract val size: Int
}
