/**
 * Copyright 2009 sshj contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.schmizz.sshj.transport.digest;

/** SHA1 Digest. */
public class SHA512
        extends BaseDigest {

    /** Named factory for SHA1 digest */
    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<Digest> {

        @Override
        public Digest create() {
            return new SHA512();
        }

        @Override
        public String getName() {
            return "sha512";
        }
    }

    /** Create a new instance of a SHA1 digest */
    public SHA512() {
        super("SHA-512", 32);
    }
}
