<p align="center">
  <img src="/images/hppimg.png">
</p>
<hr>
<h1><i>Purpose</i></h1>
Hash++ is a header-file only library that allows a user to retrieve multiple types of hashes from data, raw bytes, files, and files in nested directories. The original purpose behind this library was to create a header-file only implementation of multiple different hash algorithms. You can find a list of the <i>currently</i> supported hash algorithms below.

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

<h1><i>Using Hash++</i></h1>
Add documentation stuffs here ...

<h1><i>Notes</i></h1>
I designed this library <i>without</i> machine endianness in mind. A lot of common architectures are either little-endian or bi-endian, so, I decided to simply design it following what byte-order is most common.
This has only been tested on little-endian architectures.
