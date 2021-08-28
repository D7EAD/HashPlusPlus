/*

  getHashFromBytes.cpp
	Example to show how to get the hex representation of a hash from its bytes.

	get::getHash<uint8_t*>() -> get hash from bytes
	get::getHash() -> default -> get hash from raw data (string)
*/

#include "hashpp.h"

using namespace hashpp;

int main() {
	// assign the MD5 hash bytes of "sample text" to byteArray
	uint8_t byteArray[] = { 112, 238, 23, 56, 182, 178, 30, 44, 138, 67, 243, 165, 171, 14, 238, 113 };

	// assign the hash object to _hex from getHash<uint8_t*>() for byte arrays
	hash _hex = get::getHash<uint8_t*>(ALGORITHMS::MD5, byteArray);
	// or use .getString()

	std::cout << _hex;
}
