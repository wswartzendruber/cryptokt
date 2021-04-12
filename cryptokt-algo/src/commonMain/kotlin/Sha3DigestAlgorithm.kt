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
