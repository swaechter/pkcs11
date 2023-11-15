# Java PKCS11 Library

## Introduction

This project provides a pure Java based library to access a native PKCS11 library. It requires Java 21+ and is based on
the new Panama/FFI/FFM API. Thus, no JNI is required and the library is platform independent as long a matching memory
template is provided.

Please note, that this project is work in progress and only a few PKCS11 functions are implemented at the moment

## Tested platform and devices

This library was tested with a SafeNet eToken 5110 on the following platforms:

* Windows 11 x64
* Linux x64

Support for 32-bit platforms is not planned.

## Thanks

This library was heavily influenced by documentation and design of these projects:

* IAIK from TU Graz: https://jce.iaik.tugraz.at/
* Pkcs11Interop from Jaroslav Imrich: https://pkcs11interop.net/

The following resources were used:

* https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html
* https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html
* https://raw.githubusercontent.com/PeculiarVentures/webcrypto-local/master/errors/PKCS11.md

## License

This project is licensed under the MIT license:

```
Copyright (c) 2023 Simon Wächter

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
