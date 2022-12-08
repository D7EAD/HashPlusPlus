/*

	Basic usage of Hash++ getHash method.
		This file shows basic usage of the above described method
		and its overloads, as well as how data can be extracted
		from its returned object.
		
*/

#include "hashpp.h"

using namespace hashpp;

int main() {
	// the data we want to hash
	std::string data = "dataToHash";

	// store the resulting hash object of 'data' using SHA-256
	auto hash = get::getHash(ALGORITHMS::SHA2_256, data);

	// print the hash digest
	std::cout << hash << std::endl;
	
	// or we can be more specific...
	std::cout << hash.getString() << std::endl;
}
