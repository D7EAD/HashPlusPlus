<p align="center">
  <img src="/images/hpp.png">
</p>
<hr>
<h1><i>Purpose</i></h1>
Hash++ is a C++17 header-only library that allows a user to retrieve multiple types of hashes from data, files, and files in nested directories. The original purpose behind this library was to create a header-file only implementation of multiple different hash algorithms. You can find a list of the <i>currently</i> supported hash algorithms below.
<br>
<h1><i>Supported Algorithms</i></h1>
<ul>
  <li>MD5</li>
  <li>MD4</li>
  <li>MD2</li>
  <li>SHA-1</li>
  <li>SHA2-224</li>
  <li>SHA2-256</li>
  <li>SHA2-384</li>
  <li>SHA2-512</li>
  <li>SHA2-512/224</li>
  <li>SHA2-512/256</li>
</ul>

Hash++ also aims to be a suitable alternative to heavier, statically and dynamically-linked libraries such as OpenSSL and Crypto++. I created it keeping in mind the mindset of a programmer who simply wants a header-only file that lets them easily and comfortably <i>"just hash sh*t."</i> Does it really have to be that difficult?

No, it doesn't. 
<br>

<h1><i>Algorithm Metrics</i></h1>
*Below you can find single-threaded speed metrics of each algorithm when generating ten million hashes of 4 repetitions of the upper and lowercase alphabet, plus base 10 digits: 4(a-z+A-Z+0-9)

```
+----------------------------------------------------------------+
|    Algorithms    |            Computational Metrics            |
|------------------|---------------------------------------------|
| 64-bit test:     |           |           |                     |
|   [MD5]          | 7846   ms | 7.846   s | 1,274,535  hashes/s |
|   [MD4]          | 5783   ms | 5.783   s | 1,729,206  hashes/s |
|   [MD2]          | 181315 ms | 181.315 s | 55,153     hashes/s | 
|   [SHA1]         | 8676   ms | 8.676   s | 1,152,605  hashes/s |
|   [SHA2-224]     | 12370  ms | 12.370  s | 808,407    hashes/s |
|   [SHA2-256]     | 12943  ms | 12.943  s | 772,618    hashes/s |
|   [SHA2-384]     | 9303   ms | 9.303   s | 1,074,922  hashes/s |
|   [SHA2-512]     | 10096  ms | 10.096  s | 990,491    hashes/s |
|   [SHA2-512/224] | 8439   ms | 8.439   s | 1,184,975  hashes/s |
|   [SHA2-512/256] | 8601   ms | 8.601   s | 1,162,656  hashes/s |
|------------------|-----------|-----------|---------------------|
| 32-bit test:     |           |           |                     |
|   [MD5]          | 10070  ms | 10.070  s | 993,049    hashes/s |
|   [MD4]          | 5998   ms | 5.998   s | 1,667,222  hashes/s |
|   [MD2]          | 234746 ms | 234.746 s | 42,599     hashes/s |
|   [SHA1]         | 10075  ms | 10.075  s | 992,556    hashes/s |
|   [SHA2-224]     | 15981  ms | 15.981  s | 625,743    hashes/s |
|   [SHA2-256]     | 14805  ms | 14.805  s | 675,447    hashes/s |
|   [SHA2-384]     | 23972  ms | 23.972  s | 417,153    hashes/s |
|   [SHA2-512]     | 24785  ms | 24.785  s | 403,470    hashes/s |
|   [SHA2-512/224] | 22772  ms | 22.772  s | 439,136    hashes/s |
|   [SHA2-512/256] | 23192  ms | 23.192  s | 431,183    hashes/s |
+----------------------------------------------------------------+
*Updated as of 11/03/2022; all computed on a stock i9 12900K
```

**Below you can find single-threaded speed metrics of each algorithm when calculating a hash for a 3GB binary file.

```
+------------------------------------------+
|    Algorithms    | Computational Metrics |          
|------------------|-----------------------|
| 64-bit test:     |           |           |
|   [MD5]          | 7143   ms | 7.143   s |
|   [MD4]          | 5041   ms | 5.041   s |
|  *[MD2]          | N/A    ms | N/A     s | 
|   [SHA1]         | 8092   ms | 8.092   s |
|   [SHA2-224]     | 11245  ms | 11.245  s |
|   [SHA2-256]     | 11194  ms | 11.194  s |
|   [SHA2-384]     | 5865   ms | 5.865   s |
|   [SHA2-512]     | 5937   ms | 5.937   s |
|   [SHA2-512/224] | 5903   ms | 5.903   s |
|   [SHA2-512/256] | 5953   ms | 5.953   s |
|------------------|-----------|-----------|
| 32-bit test:     |           |           |
|   [MD5]          | 9519   ms | 9.519   s |
|   [MD4]          | 5138   ms | 5.138   s |
|  *[MD2]          | N/A    ms | N/A     s | 
|   [SHA1]         | 9239   ms | 9.239   s |
|   [SHA2-224]     | 15441  ms | 15.441  s |
|   [SHA2-256]     | 13332  ms | 13.332  s |
|   [SHA2-384]     | 18297  ms | 18.297  s |
|   [SHA2-512]     | 17741  ms | 17.741  s |
|   [SHA2-512/224] | 17910  ms | 17.910  s |
|   [SHA2-512/256] | 18550  ms | 18.550  s |
+------------------------------------------+
*Excluded due to impractically long computational times.
**Updated as of 11/15/2021; all computed on a stock i9 12900K
```

<h1><i>Using Hash++</i></h1>
My original design idea behind Hash++ was for it to be <b>simple</b>. This has remained unchanged.
<br><br>
Below you can find the signatures of the <i>only</i> functions necessary to accomplish retrieving hashes from both single or multiple sets of data, files, and files in nested directories. All functions are located in the <code>hashpp</code> namespace under class <code>get</code> (<code>hashpp::get</code>).
<br><br>
You can find examples of Hash++ in use in the <a href="/examples">/examples</a> and <a href="/tests">/tests</a> directories.
<br>
<h3><code>getHash</code></h3>
Retrieve a single hash from a single piece of data.

```cpp
// function to return a resulting hash from selected ALGORITHM and passed data
static hashpp::hash getHash(hashpp::ALGORITHMS algorithm, std::string data)
```

<h3><code>getHashes</code></h3>
Retrieve a collection of hashes from multiple pieces of data.

```cpp
// function to return a collection of resulting hashes from selected ALGORITHMS and passed data
static hashpp::hashCollection getHashes(std::vector<std::pair<hashpp::ALGORITHMS, std::vector<std::string>>> algorithmDataPairs)
```

<h3><code>getFileHash</code></h3>
Retrieve a single hash from a single file.

```cpp
// function to return a resulting hash from selected ALGORITHM and passed file
static hashpp::hash getFileHash(hashpp::ALGORITHMS algorithm, std::string path)
```

<h3><code>getFilesHashes</code></h3>
Retrieve a collection of hashes from multiple files or files in nested directories.

```cpp
// function to return a collection of resulting hashes from selected ALGORITHMS and passed files (with recursive directory support)
static hashpp::hashCollection getFilesHashes(std::vector<std::pair<hashpp::ALGORITHMS, std::vector<std::string>>> algorithmPathPairs)
```
