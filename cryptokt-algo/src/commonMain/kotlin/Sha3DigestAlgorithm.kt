/*
 * SPDX-FileCopyrightText: 2021 William Swartzendruber <wswartzendruber@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.cryptokt.algo

/**
 * The third formally published version of the U.S. Secure Hash Algorithm. This implementation
 * handles SHA3-224, SHA3-256, SHA3-384, and SHA3-512. The block and digest sizes vary.
 *
 * @property[size] The enumerated size of the instance.
 *
 * @constructor Initializes a new SHA-3 instance according to the specified digest [size].
 */
public class Sha3DigestAlgorithm(
    public val size: Sha3DigestSize
) : KeccakDigestAlgorithm(size.capacity, size.digestSize, -122, 6, -128)
