<p align="center">
  <img src="/images/hpp.png">
</p>
<hr>
<h1><i>Purpose</i></h1>
Hash++ is a header-file only library that allows a user to retrieve multiple types of hashes from data, raw bytes, files, and files in nested directories. The original purpose behind this library was to create a header-file only implementation of multiple different hash algorithms. You can find a list of the <i>currently</i> supported hash algorithms below.
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

<h1><i>Algorithm Speed Comparison</i></h1>
Below you can find speed metrics of each algorithm when generating ten-million hashes of 4 repetitions of the upper and lowercase alphabet, plus base 10 digits: 4(a-z+A-Z+0-9)

```
[MD5]          : 17132  ms | 17.132  s
[MD4]          : 11616  ms | 11.6156 s
[MD2]          : 344455 ms | 344.455 s
[SHA1]         : 19649  ms | 19.649  s
[SHA2-224]     : 26341  ms | 26.341  s
[SHA2-256]     : 27350  ms | 27.350  s
[SHA2-384]     : 42159  ms | 42.159  s
[SHA2-512]     : 43013  ms | 43.013  s
[SHA2-512/224] : 41364  ms | 41.364  s
[SHA2-512/256] : 41597  ms | 41.597  s
```

<h1><i>Using Hash++</i></h1>
My original design idea behind Hash++ was for it to be <b>simple</b>. This has remained unchanged.
<br><br>
Below, you can find the signatures of the <i>only</i> functions necessary to accomplish retrieving hashes from both single or multiple sets of data, raw bytes, files, and files in nested directories. All functions are located in the <code>hashpp</code> namespace under class <code>get</code> (<code>hashpp::get</code>).
<br><br>
You can find examples of Hash++ in use in the <a href="/examples">/examples</a> directory.
<br>
<h3><code>getHash</code></h3>
Retrieve a single hash from a single piece of data.

```cpp
// function to return a resulting hash from selected ALGORITHM and passed data (byte array or string)
template <typename _Ty = std::string>
constexpr static hashpp::hash getHash(hashpp::ALGORITHMS algorithm, _Ty data);
```

<h3><code>getHashes</code></h3>
Retrieve a collection of hashes from multiple pieces of data.

```cpp
// function to return a collection of resulting hashes from selected ALGORITHMS and passed data (byte arrays or strings)
template <typename _Ty = std::string>
constexpr static hashpp::hashCollection getHashes(std::vector<std::pair<hashpp::ALGORITHMS, std::vector<_Ty>>> algorithmDataPairs)
```

<h3><code>getFileHash</code></h3>
Retrieve a single hash from a single file.

```cpp
// function to return a resulting hash from selected ALGORITHM and passed file
static hashpp::hash getFileHash(hashpp::ALGORITHMS algorithm, std::string path)
```

<h3><code>getFilesHashes</code></h3>
Retrieve a collection of hashes from multiple files or files in directories.

```cpp
// function to return a collection of resulting hashes from selected ALGORITHMS and passed files (with recursive directory support)
static hashpp::hashCollection getFilesHashes(std::vector<std::pair<hashpp::ALGORITHMS, std::vector<std::string>>> algorithmPathPairs)
```

<h3><code>getBytes</code></h3>
Retrieve one or more arrays of hash bytes from one or more pieces of data.

```cpp
// return the bytes of the resulting hash of passed data based on supplied ALGORITHM (returned array is heap-allocated)
constexpr static uint8_t* getBytes(hashpp::ALGORITHMS algorithm, std::string data)
```
```cpp
// return vector containing the bytes of the resulting hashes of passed data based on supplied ALGORITHMS (returned arrays in vector are heap-allocated)
constexpr static std::vector<uint8_t*> getBytes(std::vector<std::pair<hashpp::ALGORITHMS, std::vector<std::string>>> algorithmDataPairs)
```
<br>
<h1><i>Notes</i></h1>
I designed this library <i>without</i> machine endianness in mind. A lot of common architectures are either little-endian or bi-endian, so, I decided to simply design it following what byte-order is most common. This has only been tested on little-endian architectures.
