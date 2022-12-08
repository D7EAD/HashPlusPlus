<h1>Keyed-Hash Message Authentication Codes (HMACs)</h1>
<p>While they may sound considerably more complicated, HMACs aren't too different from cryptographic hashes at the end of the day. HMACs are keyed hashes of data meaning, simply, that an HMAC is used to generate a unique hash digest of data when that data is paired with another specific piece of data--a key.</p>

<p>Take, for instance, the simple example hash function of <code>H(x) = y</code> where <code>H</code> is our hash function, <code>x</code> is our input data, and <code>y</code> is our output hash digest. The output digest depends on two things:</p>

- The hash function in use.
- The input supplied to said function.

<p>Now, take, for instance, the following naive keyed hash algorithm *<code>H(x + k) = y</code> where <code>H</code> is our hash function, <code>x</code> is our input data, <code>k</code> is our key data, and <code>y</code> is our output hash digest. The output digest <b>now</b> depends on three things:</p>

- The hash function in use.
- The input supplied to said function.
- The key data.

<p>Hash functions provide collision-resistance whereas an HMAC provides both collision-resistance and <i>unforgeability</i>. Due to this provided element of unforgeability, HMACs are used in combination with hash algorithms to prove not only that data is unmodified, but that whoeever calculated the hash for said data did so with the correct key--otherwise the incorrect HMAC would result.</p>

<p>Simply put, a hash allows for <b>verification of the authenticity of data</b> whereas an HMAC allows for <b>verification of both the authenticity of data and the originator of said data</b>.</p>

<p><i>*Keep in mind that HMACs do not simply operate as a hash function <code>H</code> applied on the key <code>k</code> appended to data <code>x</code>. How HMACs are calculated is a bit more nuanced. You can read more about the RFC specification <a href="https://www.rfc-editor.org/rfc/rfc2104">here</a>.</i></p>

<br>
<h1>Using Hash++</h1>
Hash++ offers a simple set of methods to generate one or multiple HMACs given data and an associated key. You can find the signatures for the functions below.

```
static hashpp::hashCollection getHMACs(const HMAC_DataContainer& keyDataSet);
static hashpp::hashCollection getHMACs(const std::vector<HMAC_DataContainer>& keyDataSets);
static hashpp::hashCollection getHMACs(const std::initializer_list<HMAC_DataContainer>& keyDataSets)
static hashpp::hashCollection getHashes(const std::initializer_list<DataContainer>& dataSets);
template <class... _Ts, ...> static hashpp::hashCollection getHMACs(hashpp::ALGORITHMS algorithm, const std::string& key, const _Ts&... data);
```
