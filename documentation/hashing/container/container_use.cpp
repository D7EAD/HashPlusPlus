/*

	Basic usage and examples of Hash++ container class Container.
		This container can be used to store paths to files to be hashed,
		data to be hashed, keys to use in generating HMACs of contained data,
		the algorithm to use to hash the contained data, etc.

		This container and its aliases are used in several function overloads
		where a developer may want to pass several sets of data and use a
		different hashing algorithm for each set of data.

*/

#include "hashpp.h"

using namespace hashpp;

int main() {
	// instantiation, assignment via member functions
	DataContainer cont1;
	cont1.setData("dataToHash1", "dataToHash2");
	cont1.appendData("moreDataToHash1", "moreDataToHash2");
	cont1.setAlgorithm(ALGORITHMS::SHA2_224);

	// instantiation, assignment via variadic data constructor
	DataContainer cont2(ALGORITHMS::SHA2_256, "dataToHash1", "dataToHash2", "moreDataToHash1", "moreDataToHash2");

	// instantiation, assignment via vector constructor
	std::vector<std::string> data = { "dataToHash1", "dataToHash2", "moreDataToHash1", "moreDataToHash2" };
	DataContainer cont3(ALGORITHMS::SHA2_384, data);

	// these containers can then be passed to their respective library function overloads
	// as an initializer list or vector
	std::vector<DataContainer> containers = { cont1, cont2, cont3 };
	auto _hashes1 = get::getHashes(containers);
	auto _hashes2 = get::getHashes({ cont1, cont2, cont3 });
}
