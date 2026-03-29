## HashBlazer  

<b>HashBlazer</b> is an open-source library that provides implementations of various hashing algorithms along with command-line utilities for hash calculation.    

| Algorithm | Utility |is implemented|
|:---:|:-----------:|:------:|
|MD5|md5sum|✅|
|SHA1|sha1sum|❌|
|SHA224|sha224sum|❌|
|SHA256|sha256sum|❌|
|SHA384|sha384sum|❌|
|SHA512|sha512sum|❌|

### Build

#### Build library only:
To build the HashBlazer library without utilities:
```bash
$ cd <project-root-directory>
$ mkdir build && cd build
$ cmake .. -DBUILD_HASHSUM_UTILS=OFF
$ cmake --build . --parallel $(nproc)
```
#### Build library + utilities
To build the library along with hash utilities (md5sum, sha1sum, etc.) :
```bash
$ cd <project-root-directory>
$ mkdir build && cd build
$ cmake ..
$ cmake --build . --parallel $(nproc)
```
#### Build tests

By default, tests are enabled. To disable them during configuration:
```bash
$ cmake .. -DBUILD_TESTING=OFF
```