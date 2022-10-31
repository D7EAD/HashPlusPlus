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
Below you can find single-threaded speed metrics of each algorithm when generating ten million hashes of 4 repetitions of the upper and lowercase alphabet, plus base 10 digits: 4(a-z+A-Z+0-9)

```
+----------------------------------------------------------------+
|    Algorithms    |            Computational Metrics            |
|------------------|---------------------------------------------|
| 64-bit test:     |           |           |                     |
|   [MD5]          | 8793   ms | 8.793   s | 1,137,268  hashes/s |
|   [MD4]          | 7258   ms | 7.258   s | 1,377,790  hashes/s |
|   [MD2]          | 323220 ms | 323.220 s | 30,939     hashes/s | 
|   [SHA1]         | 10020  ms | 10.020  s | 998,004    hashes/s |
|   [SHA2-224]     | 13442  ms | 13.442  s | 743,937    hashes/s |
|   [SHA2-256]     | 13668  ms | 13.668  s | 731,636    hashes/s |
|   [SHA2-384]     | 10324  ms | 10.324  s | 968,617    hashes/s |
|   [SHA2-512]     | 10680  ms | 10.680  s | 936,330    hashes/s |
|   [SHA2-512/224] | 9748   ms | 9.748   s | 1,025,852  hashes/s |
|   [SHA2-512/256] | 9965   ms | 9.965   s | 1,003,512  hashes/s |
|------------------|-----------|-----------|---------------------|
| 32-bit test:     |           |           |                     |
|   [MD5]          | 10707  ms | 10.707  s | 933,968    hashes/s |
|   [MD4]          | 7815   ms | 7.815   s | 1,279,591  hashes/s |
|   [MD2]          | 204250 ms | 204.250 s | 48,960     hashes/s |
|   [SHA1]         | 11942  ms | 11.942  s | 837,381    hashes/s |
|   [SHA2-224]     | 16518  ms | 16.518  s | 605,400    hashes/s |
|   [SHA2-256]     | 16306  ms | 16.306  s | 613,271    hashes/s |
|   [SHA2-384]     | 25171  ms | 25.171  s | 397,283    hashes/s |
|   [SHA2-512]     | 26746  ms | 26.746  s | 373,888    hashes/s |
|   [SHA2-512/224] | 24418  ms | 24.418  s | 409,534    hashes/s |
|   [SHA2-512/256] | 24343  ms | 24.343  s | 410,796    hashes/s |
+----------------------------------------------------------------+
*Updated as of 11/15/2021; all computed on a stock i9 12900K
```

Below you can find single-threaded speed metrics of each algorithm when calculating a hash for a 3GB binary file.

```
+------------------------------------------+
|    Algorithms    | Computational Metrics |          
|------------------|-----------------------|
| 64-bit test:     |           |           |
|   [MD5]          | 7143   ms | 7.143   s |
|   [MD4]          | 5121   ms | 5.121   s |
|   [MD2]          | 323220 ms | 323.220 s | 
|   [SHA1]         | 10020  ms | 10.020  s |
|   [SHA2-224]     | 13442  ms | 13.442  s |
|   [SHA2-256]     | 13668  ms | 13.668  s |
|   [SHA2-384]     | 10324  ms | 10.324  s |
|   [SHA2-512]     | 10680  ms | 10.680  s |
|   [SHA2-512/224] | 9748   ms | 9.748   s |
|   [SHA2-512/256] | 9965   ms | 9.965   s |
|------------------|-----------|-----------|
| 32-bit test:     |           |           |
|   [MD5]          | 10707  ms | 10.707  s |
|   [MD4]          | 7815   ms | 7.815   s |
|   [MD2]          | 204250 ms | 204.250 s |
|   [SHA1]         | 11942  ms | 11.942  s |
|   [SHA2-224]     | 16518  ms | 16.518  s |
|   [SHA2-256]     | 16306  ms | 16.306  s |
|   [SHA2-384]     | 25171  ms | 25.171  s |
|   [SHA2-512]     | 26746  ms | 26.746  s |
|   [SHA2-512/224] | 24418  ms | 24.418  s |
|   [SHA2-512/256] | 24343  ms | 24.343  s |
+------------------------------------------+
*Updated as of 11/15/2021; all computed on a stock i9 12900K
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
