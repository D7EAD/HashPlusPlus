/*

	Basic usage of Hash++ getHMAC method.
		This file shows basic usage of the above described method
		and its overloads, as well as how data can be extracted
		from its returned object.
		
*/

#include "hashpp.h"

using namespace hashpp;

int main() {
	// data we want to get HMAC of
	std::string dataToHash = "Hello World!";
	
	// key to use for HMAC
	std::string key = "secret";
	
	// get HMAC of dataToHash using SHA-256
	auto hmac = get::getHMAC(ALGORITHMS::SHA2_256, key, dataToHash);

	// print out the hash
	std::cout << "HMAC: " << hmac << std::endl;

	// output:
	//   6fa7b4dea28ee348df10f9bb595ad985ff150a4adfd6131cca677d9acee07dc6
}
