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
Hash++ offers a simple set of methods to take advantage of the cryptographic-magic described above.
