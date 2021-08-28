/*

  getSimpleHashes.cpp
    Example showing how to retrieve and iterate several hashes from several pieces of simple data.

*/

#include "hashpp.h"

using namespace hashpp;

int main() {
	// get a hash collection containing the MD5 and MD4 hashes for all passed data
	hashCollection collection = get::getHashes({ {ALGORITHMS::MD4, {"data1", "data2", "data3",
		                                                        "data4", "data5", "data6",
		                                                        "data7", "data8", "data9"} },
						     {ALGORITHMS::MD5, {"data1", "data2", "data3",
					                                "data4", "data5", "data6",
					                                "data7", "data8", "data9"} } });

	// the method above of getting multiple hashes is equivalent to the below
	std::vector<std::string> data1 = { "data1", "data2", "data3", "data4", "data5", "data6", "data7", "data8", "data9" };
	std::vector<std::string> data2 = { "data1", "data2", "data3", "data4", "data5", "data6", "data7", "data8", "data9" };
	hashCollection collection2 = get::getHashes({ {ALGORITHMS::MD4, data1}, {ALGORITHMS::MD5, data2} });
  
	// to iterate over hashes from a specific algorithm (in the order they were supplied)
	for (auto i : collection["MD5"]) {
		std::cout << i << std::endl;
	}
	for (auto i : collection["MD4"]) {
		std::cout << i << std::endl;
	}
	
	// the above will iterate through the hashes of "data1"-"data9" for both MD5 and MD4
}
