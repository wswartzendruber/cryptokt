/*
 * SPDX-FileCopyrightText: 2021 William Swartzendruber <wswartzendruber@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.cryptokt.algo

/**
 * The SHAKE128 extendable output function. The block size is 32 bytes and the digest size is
 * configurable.
 *
 * @constructor Initializes a new SHAKE128 instance with the specified [digestSize].
 */
public class Shake128DigestAlgorithm(
    digestSize: Int,
) : KeccakDigestAlgorithm(32, digestSize, -97, 31, -128)
