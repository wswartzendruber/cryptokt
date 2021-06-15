/*
 * SPDX-FileCopyrightText: 2021 William Swartzendruber <wswartzendruber@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.cryptokt.algo

/**
 * The SHAKE256 extendable output function. The block size is 64 bytes and the digest size is
 * configurable.
 *
 * @constructor Initializes a new SHAKE256 instance with the specified [digestSize].
 */
public class Shake256DigestAlgorithm(
    digestSize: Int,
) : KeccakDigestAlgorithm(64, digestSize, -97, 31, -128)
