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
**Updated as of 11/03/2022; all computed on a stock i9 12900K
```
