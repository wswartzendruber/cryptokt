/*
 * SPDX-FileCopyrightText: 2021 William Swartzendruber <wswartzendruber@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.cryptokt.algo

/**
 * Represents the possible digest sizes for SHA-3.
 */
public enum class Sha3DigestSize(
    internal val digestSize: Int,
    internal val capacity: Int,
) {
    /** SHA3-224. The block size is 144 bytes and the digest size is 28 bytes. */
    _224(28, 56),
    /** SHA3-256. The block size is 136 bytes and the digest size is 32 bytes. */
    _256(32, 64),
    /** SHA3-384. The block size is 104 bytes and the digest size is 48 bytes. */
    _384(48, 96),
    /** SHA3-512. The block size is 72 bytes and the digest size is 64 bytes. */
    _512(64, 128),
}
