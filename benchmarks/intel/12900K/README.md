<h1>Hash++ Benchmark: Intel i9 12900K</h1>
Below you can find the benchmarks for a stock i9 12900K computing 10 million hashes using Hash++. Each hash is of the result of four concatenations of the lower and uppercase alphabet, plus base ten digits.
<br><br>

<pre>
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
*Updated as of 11/03/2022
</pre>

**Below you can find single-threaded speed metrics of each algorithm when calculating a hash for a 3GB binary file.

<pre>
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
**Updated as of 11/03/2022
</pre>
