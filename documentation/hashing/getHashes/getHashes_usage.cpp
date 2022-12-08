/*

	Basic usage of Hash++ getHashes method.
		This file shows basic usage of the above described method
		and its overloads, as well as how data can be extracted
		from its returned object.
		
*/

#include "hashpp.h"

using namespace hashpp;

int main() {
	// a container holding data to be hashed and algorithm to use
	DataContainer cont1;
	cont1.setAlgorithm(ALGORITHMS::SHA2_256);
	cont1.setData("dataToHash1", "dataToHash2", "dataToHash3");

	// acquiring the hashes of the data contained in the above
	// container using its set algorithm (SHA2-256).
	hashCollection hashes = get::getHashes(cont1);

	// printing the resulting hashes via hashCollection::operator[]
	// with specific algorithm name
	for (auto& hash : hashes["SHA2-256"]) {
		std::cout << hash << std::endl;
	}
}
