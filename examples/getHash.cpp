/*

  getHash.cpp
    Example showing how to get the hash of simple data.

*/

#include "hashpp.h"

using namespace hashpp;

int main() {
	// string that we want to get the hash of
	std::string dataToBeHashed = "sample text";

	// hashes can be printed directly like normal
	// output: bc658c641ef71739fb9995bded59b21150bbff4367f6e4e4c7934b489b9d2c00
	std::cout << get::getHash(ALGORITHMS::SHA2_256, dataToBeHashed) << std::endl;

	// ... or, we can capture the returned hashpp::hash object
	hash _hex = get::getHash(ALGORITHMS::SHA2_256, dataToBeHashed);
	std::cout << _hex << std::endl;

	// ... or, we can simply capture the std::string object of the hash's hex string
	std::string _hexString = get::getHash(ALGORITHMS::SHA2_256, dataToBeHashed).getString();
}
