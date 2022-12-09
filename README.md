<p align="center">
  <img src="/images/hpp.png">
</p>
<hr>
<h1><i>Purpose</i></h1>
Hash++ is a C++17 header-only library that allows a user to retrieve multiple types of hashes from data, files, and files in nested directories. The original purpose behind this library was to create a header-file only implementation of multiple different hash algorithms. You can find a list of the <i>currently</i> supported hash algorithms below.
<br>
<h1><i>Supported Algorithms</i></h1>

|    Algorithm    |    HMAC Support?    |
| :-------------: | :-----------------: |
| MD5             | :heavy_check_mark:  |
| MD4             | :heavy_check_mark:  |
| MD2             | :heavy_check_mark:  |
| SHA1            | :heavy_check_mark:  |
| SHA2-224        | :heavy_check_mark:  |
| SHA2-256        | :heavy_check_mark:  |
| SHA2-384        | :heavy_check_mark:  |
| SHA2-512        | :heavy_check_mark:  |
| SHA2-512/224    | :heavy_check_mark:  |
| SHA2-512/256    | :heavy_check_mark:  |

Hash++ also aims to be a suitable alternative to heavier, statically and dynamically-linked libraries such as OpenSSL and Crypto++. I created it keeping in mind the mindset of a programmer who simply wants a header-only file that lets them easily and comfortably <i>"just hash sh*t."</i> Does it really have to be that difficult?

No, it doesn't. 
<br>


<h1><i>Documentation</i></h1>
You can find detailed documentation in the <a href="/documentation">/documentation</a> directory.

<h1><i>Algorithm Metrics</i></h1>
Below you can view benchmarks of Hash++ computing 10 million hashes for each algorithm. Each benchmark is based on the hashing of four concatenations of the lower and uppercase alphabet, plus base ten digits. 

- <a href="/benchmarks/intel/12900K">i9 12900K Benchmark</a>
- <a href="/benchmarks/amd/5900HX">Ryzen 9 5900HX Benchmark</a>
