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

/**
 * Represents the possible digest sizes for SHA3.
 *
 * @property[digestSize] The digest size in bytes.
 */
public enum class Sha3DigestSize(
    public val digestSize: Int,
    internal val capacity: Int,
) {
    /** SHA3-224 */
    _224(28, 56),
    /** SHA3-256 */
    _256(32, 64),
    /** SHA3-384 */
    _384(48, 96),
    /** SHA3-512 */
    _512(64, 128),
}
