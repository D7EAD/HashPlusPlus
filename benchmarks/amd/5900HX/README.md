<h1>Benchmark: AMD Ryzen 9 5900HX</h1>
Below you can find the benchmarks for a stock Ryzen 9 5900HX computing 10 million hashes using Hash++. Each hash is the result of four concatenations of the lower and uppercase alphabet plus base ten digits.
<br><br>

<pre>
+----------------------------------------------------------------+
|    Algorithms    |            Computational Metrics            |
|------------------|---------------------------------------------|
| 64-bit test:     |           |           |                     |
|   [MD5]          | 10140  ms | 10.140  s | 986,193    hashes/s |
|   [MD4]          | 8922   ms | 8.922   s | 1,120,825  hashes/s |
|   [MD2]          | 253154 ms | 253.154 s | 39,502     hashes/s | 
|   [SHA1]         | 12641  ms | 12.641  s | 791,077    hashes/s |
|   [SHA2-224]     | 16908  ms | 16.908  s | 591,436    hashes/s |
|   [SHA2-256]     | 17143  ms | 17.143  s | 583,328    hashes/s |
|   [SHA2-384]     | 12931  ms | 12.931  s | 773,335    hashes/s |
|   [SHA2-512]     | 14814  ms | 14.814  s | 675,037    hashes/s |
|   [SHA2-512/224] | 11806  ms | 11.806  s | 847,027    hashes/s |
|   [SHA2-512/256] | 11829  ms | 11.829  s | 845,380    hashes/s |
|------------------|-----------|-----------|---------------------|
| 32-bit test:     |           |           |                     |
|   [MD5]          | 15288  ms | 15.288  s | 654,108    hashes/s |
|   [MD4]          | 11704  ms | 11.704  s | 854,409    hashes/s |
|   [MD2]          | 319056 ms | 319.056 s | 31,342     hashes/s |
|   [SHA1]         | 18317  ms | 18.317  s | 545,941    hashes/s |
|   [SHA2-224]     | 23672  ms | 23.672  s | 422,440    hashes/s |
|   [SHA2-256]     | 23643  ms | 23.643  s | 422,958    hashes/s |
|   [SHA2-384]     | 46221  ms | 46.221  s | 216,352    hashes/s |
|   [SHA2-512]     | 47700  ms | 47.700  s | 209,644    hashes/s |
|   [SHA2-512/224] | 44673  ms | 44.673  s | 223,849    hashes/s |
|   [SHA2-512/256] | 45009  ms | 45.009  s | 222,178    hashes/s |
+----------------------------------------------------------------+
*Updated as of 12/09/2022
</pre>

**Below you can find single-threaded speed metrics of each algorithm when calculating a hash for a 3GB binary file.

<pre>
+------------------------------------------+
|    Algorithms    | Computational Metrics |          
|------------------|-----------------------|
| 64-bit test:     |           |           |
|   [MD5]          | 27547  ms | 27.547  s |
|   [MD4]          | 18792  ms | 18.792  s |
|  *[MD2]          | N/A    ms | N/A     s | 
|   [SHA1]         | 29517  ms | 29.517  s |
|   [SHA2-224]     | 38259  ms | 38.259  s |
|   [SHA2-256]     | 39529  ms | 39.529  s |
|   [SHA2-384]     | 19100  ms | 19.100  s |
|   [SHA2-512]     | 18950  ms | 18.950  s |
|   [SHA2-512/224] | 18914  ms | 18.914  s |
|   [SHA2-512/256] | 19101  ms | 19.101  s |
|------------------|-----------|-----------|
| 32-bit test:     |           |           |
|   [MD5]          | 27889  ms | 27.889  s |
|   [MD4]          | 17807  ms | 17.807  s |
|  *[MD2]          | N/A    ms | N/A     s | 
|   [SHA1]         | 37695  ms | 37.695  s |
|   [SHA2-224]     | 49349  ms | 49.349  s |
|   [SHA2-256]     | 48687  ms | 48.687  s |
|   [SHA2-384]     | 85244  ms | 85.244  s |
|   [SHA2-512]     | 84989  ms | 84.989  s |
|   [SHA2-512/224] | 84926  ms | 84.926  s |
|   [SHA2-512/256] | 84966  ms | 84.966  s |
+------------------------------------------+
*Excluded due to impractically long computational times.
**Updated as of 12/09/2022
</pre>
