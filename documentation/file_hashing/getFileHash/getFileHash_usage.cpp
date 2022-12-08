/*

	Basic usage of Hash++ getFileHash method.
		This file shows basic usage of the above described method
		and its overloads, as well as how data can be extracted
		from its returned object.
		
*/

#include "hashpp.h"

using namespace hashpp;

int main() {
	// path to file we want to hash (test.txt)
	std::string pathToFile = "N:/source/test.txt";

	// store the resulting hash object of the file using SHA-256
	auto hash = get::getFileHash(ALGORITHMS::SHA2_256, pathToFile);

	// print the hash digest
	std::cout << hash << std::endl;
	
	// or we can be more specific...
	std::cout << hash.getString() << std::endl;
	
	// output:
	//    4de0d727216e14760010efdb0cccf577853d7da4e122a507b422148940f4aa34
}
