<h1>Hashing</h1>
Hashing, in simple terms, is the cryptographic process of assigning a unique fingerprint to data such that no other data will produce the same fingerprint as another piece of data.
<br><br>
In mathematical terms, hashing is the functional process of mapping any arbitrary data <code>X</code> to a fixed-size, unique, and seemingly nonsensical value <code>D</code>. Hashing algorithms are one-way functions such that, given an input <code>x</code> to some hash function <code>H</code>, it is facile to compute the output hash digest <code>D</code>; however, given only some hash function <code>H</code> and an associated output digest <code>D</code>, it is infeasible to compute the original input data <code>x</code>.
<br><br>
Simply, a one-way function <code>H(x) = D</code> is one such function that satisfies all constraints such that...

- <code>D</code> is easily computed given <code>x</code>.
- <code>H</code>'s output range is known.
- Given only output <code>D</code> and function <code>H</code>, <code>x</code> is infeasibly computed such that <code>H(x) = D</code>.

Given this inherent infeasibility of recovering initial input data to a given hash function, they are useful for a number of security purposes such as:

- Message and file integrity verification.
- Password verification.
- Signature/identifier generation and verification.
- Key Derivation Functions (KDFs).
- Proof-of-Work.
- Blockchain Technology.
- Public-Key Cryptography.
- CSPRNGs.

<h1>Using Hash++</h1>
Hash++ offers a simple set of methods to take advantage of the cryptographic-magic described above. You can generate simple hashes using the functions described below.

```
static hashpp::hash getHash(hashpp::ALGORITHMS algorithm, const std::string& data);
static hashpp::hashCollection getHashes(const DataContainer& dataSet)
static hashpp::hashCollection getHashes(const std::vector<DataContainer>& dataSets);
static hashpp::hashCollection getHashes(const std::initializer_list<DataContainer>& dataSets);
template <class... _Ts, ...> static hashpp::hashCollection getHashes(hashpp::ALGORITHMS algorithm, const _Ts&... data);
```
<br>
Some function overloads found in Hash++ make use of a container class <code>Container</code> with aliases <code>DataContainer</code>, <code>HMAC_DataContainer</code>, and <code>FilePathsContainer</code>. This class allows developers to contain all data associated with a particular hash algorithm in one name, making it easier to pass several of them, if desired, and, in turn, several sets of data to hash. You can find the detailed implementation of the class below.
https://github.com/D7EAD/HashPlusPlus/blob/8bf4d2971f5fab4ad0df75ea6f71a012841c504e/documentation/hashing/container/container.cpp#L1-L100

<br>
While the class may seem daunting at first, below you can find examples of its use and instantiation, as well as how it can be passed to certain function overloads.
https://github.com/D7EAD/HashPlusPlus/blob/8bf4d2971f5fab4ad0df75ea6f71a012841c504e/documentation/hashing/container/container_use.cpp#L14-L37

<br>
As you can see above, when given a properly created <code>Container</code>, the library function <code>getHashes(...)</code> can easily calculate and retrieve the hash digests of the passed data contained in the container(s). The function <code>getHashes(...)</code> itself, though, returns a <code>hashCollection</code> object. This object can be parsed quite easily:
https://github.com/D7EAD/HashPlusPlus/blob/b7fbc10fc627ab21c39a51698882641e1073c78e/documentation/hashing/getHashes/getHashes_usage.cpp#L10-L29
