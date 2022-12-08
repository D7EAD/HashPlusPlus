<h1>Keyed-Hash Message Authentication Codes (HMACs)</h1>
<p>While they may sound considerably more complicated, HMACs aren't too different from cryptographic hashes at the end of the day. HMACs are keyed hashes of data meaning, simply, that an HMAC is used to generate a unique hash digest of data when that data is paired with another specific piece of data--a key.</p>

<p>Take, for instance, the simple example hash function of <code>H(x) = y</code> where <code>H</code> is our hash function, <code>x</code> is our input data, and <code>y</code> is our output hash digest. The output digest depends on two things:</p>

- The hash function in use.
- The input supplied to said function.

<p>Now, take, for instance, the following naive keyed hash algorithm *<code>H(x + k) = y</code> where <code>H</code> is our hash function, <code>x</code> is our input data, <code>k</code> is our key data, and <code>y</code> is our output hash digest. The output digest <b>now</b> depends on three things:</p>

- The hash function in use.
- The input supplied to said function.
- The key data.

<p>Hash functions provide collision-resistance whereas an HMAC provides both collision-resistance and <i>unforgeability</i>. Due to this provided element of unforgeability, HMACs are used in combination with hash algorithms to prove not only that data is unmodified, but that whoever calculated the hash for said data did so with the correct key--otherwise the incorrect HMAC would result.</p>

<p>Simply put, a hash allows for <b>verification of the authenticity of data</b> whereas an HMAC allows for <b>verification of both the authenticity of data and the originator of said data</b>.</p>

<p><i>*Keep in mind that HMACs do not simply operate as a hash function <code>H</code> applied on a key <code>k</code> appended to data <code>x</code>. How HMACs are calculated is a bit more nuanced. Hash algorithms are not HMACs and vice-versa--the HMAC mechanism works atop existing hash algorithms. You can read more about the RFC specification <a href="https://www.rfc-editor.org/rfc/rfc2104">here</a>.</i></p>

<br>
<h1>Using Hash++</h1>
Hash++ offers a simple set of methods to generate one or multiple HMACs given data and an associated key. You can find the signatures for the functions below.

```
static hashpp::hash getHMAC(hashpp::ALGORITHMS algorithm, const std::string& key, const std::string& data;
static hashpp::hashCollection getHMACs(const HMAC_DataContainer& keyDataSet);
static hashpp::hashCollection getHMACs(const std::vector<HMAC_DataContainer>& keyDataSets);
static hashpp::hashCollection getHMACs(const std::initializer_list<HMAC_DataContainer>& keyDataSets);
template <class... _Ts, ...> static hashpp::hashCollection getHMACs(hashpp::ALGORITHMS algorithm, const std::string& key, const _Ts&... data);
```

<br>
You can easily generate an HMAC for a single piece of data using Hash++. See below for an example.
https://github.com/D7EAD/HashPlusPlus/blob/0ac434933e4d54b584b810d863a9f1a4a4f5f7b4/documentation/HMACs/getHMAC/getHMAC_usage.cpp#L10-L29

<br>
In order to generate several HMACs for several pieces of data, we can use a <code>Container</code> alias <code>HMAC_DataContainer</code> (if you have not read about the Container class used by Hash++, please see the documentation for <b>Hashing</b>). See below for an example.
https://github.com/D7EAD/HashPlusPlus/blob/fc5edb76cd829794a3fb34c416df7431653044e0/documentation/HMACs/getHMACs/getHMACs_usage.cpp#L14-L42
