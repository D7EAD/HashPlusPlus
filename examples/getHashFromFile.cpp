/*

	getHashFromFile
		Example to show how to get the hash of a single file.

*/

#include "hashpp.h"

using namespace hashpp;

int main() {
	// get a hash of item1.txt in relative directory folder1
	hash _a = get::getFileHash(ALGORITHMS::MD5, "./folder1/item1.txt");

	std::cout << _a << std::endl;
	// or _a.getString()

	// output: 4817a091b69d5e89d7d5757e6ce19609 -> ./folder1/item1.txt
}
