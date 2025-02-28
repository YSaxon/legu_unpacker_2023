# Legu Unpacker

This is a script to unpack Android applications protected by Tencent Legu. It presently works with versions
**4.1.0.15**, **4.1.0.18**, **4.1.0.20**, and **4.1.0.31** of Legu, and is easily extendable to unsupported versions. See [reverse engineering tips](reverse_engineering_tips/reverse_engineering_tips.md) for detailed tips on how to go about finding the keys for a version we don't already have. It's a fun and instructive reverse-engineering exercise.

This is a fork of [legu_unpacker_2019](https://github.com/quarkslab/legu_unpacker_2019) by Romain Thomas, updated to add new encryption methods and keys (and make it all extendable for the future) and replace dependencies that were difficult to get working on modern Python installations.

Original blog post: https://blog.quarkslab.com/a-glimpse-into-tencents-legu-packer.html

## Overview

The original DEX files are located in ``assets/0OO00l111l1l`` with the following layout:

<p align="center" >
<img src="imgs/packed_file.png"/><br />
</p>

One can find the details of this structure in the Kaitai file: [legu_packed_file.ks](./legu_packed_file.ksy)

The *hashmap* embedded in the second part is described in the [legu_hashmap.ks](./legu_hashmap.ksy) file:

<p align="center" >
<img src="imgs/hashmap.png"/><br />
</p>


## Get Started

The sample [com.intotherain.voicechange.apk](./samples/com.intotherain.voicechange.apk) is a [suspicious application](https://www.virustotal.com/gui/file/708e6967920dcf2789b7183d714e73ab79a2f8b3ca71929b12aadeb2c58c2867/detection)
that can be unpacked as follows:

```bash
$ python ./unpack.py ./samples/com.intotherain.voicechange.apk

[+] Legu version: 4.1.0.15
[+] Password is 'IPk2Hw7AKTuIQBlc'
[+] Number of dex files: 1
[+] Unpacking #1 DEX files ...
[+] dex 0 compressed size:   0x1619a3
[+] dex 0 uncompressed size: 0x5671f8

[+] Unpacking #1 hashmap ...
[+] hashmap 0 compressed size:   0x4399c
[+] hashmap 0 uncompressed size: 0x95558

[+] Unpacking #1 packed methods ...
[+] packed methods 0 compressed_size:   0xf4636
[+] packed methods 0 uncompressed_size: 0x1e3072

[+] Stage 2: Patching DEX files
[+] Unpacked APK: unpacked.apk
```

The unpacked DEX files are located in the ``unpacked.apk`` file.

## Requirements

- Python >= 3.7
- Kaitai Struct
- LIEF
- [pyucl](https://github.com/jap/pyucl)

## Usage with docker

**Building the container:**

```
docker build . -t legu-unpacker
```

**Running the container:**

```
docker run --rm -v "$(pwd)":/unpacker legu-unpacker python ./unpack.py ./samples/com.intotherain.voicechange.apk
```

**Untagging the docker image:**

```
docker image rm legu-unpacker
```
