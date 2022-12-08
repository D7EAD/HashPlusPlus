/*

	Basic usage of Hash++ getFileHashes method.
		This file shows basic usage of the above described method
		and its overloads, as well as how data can be extracted
		from its returned object.
		
*/

#include "hashpp.h"

using namespace hashpp;

int main() {
	// create a FilePathsContainer object
	FilePathsContainer path_cont1;
	
	// set its algorithm and some paths
	path_cont1.setAlgorithm(ALGORITHMS::SHA2_256);
	path_cont1.setData("N:/source/test.txt", "N:/source/test2.txt", "N:/source/test3.txt");
	
	// get the hashes of each file via get::getFilesHashes
	// and store them in a hashCollection object
	hashCollection hashes = get::getFilesHashes(path_cont1);

	// parse and print the hashes
	for (auto& hash : hashes["SHA2-256"]) {
		std::cout << hash << std::endl;
	}

	// output:
	//   4de0d727216e14760010efdb0cccf577853d7da4e122a507b422148940f4aa34
	//   7c88d6bc28e9bd6660b96cfa3b69cdbaaaf0187047267106842841357ac03bd8
	//   44d25e664ce6d6e82beb7a14fe312d7c09c5dc107668a6d40449bc24938e5c73
}
