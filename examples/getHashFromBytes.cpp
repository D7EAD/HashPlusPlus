/*

  getHashFromBytes.cpp
    Example to show how to get the hex representation of a hash from its bytes.
  
    get::getHash<uint8_t*>() -> get hash from bytes
    get::getHash() -> default -> get hash from raw data (string)
*/

#include "hashpp.h"

using namespace hashpp;

int main() {
	// assign the SHA2-256 hash bytes of "sample text" to byteArray
	uint8_t* byteArray = get::getBytes(ALGORITHMS::SHA2_256, "sample text");

	// assign the hash object to _hex from getHash<uint8_t*>() for byte arrays
	hash _hex = get::getHash<uint8_t*>(ALGORITHMS::SHA2_256, byteArray);
	// or use .getString()

	std::cout << _hex;

	delete[] byteArray;
}
