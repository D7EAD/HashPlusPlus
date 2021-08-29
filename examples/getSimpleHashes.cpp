/*

  getSimpleHashes.cpp
    Example showing how to retrieve and iterate several hashes from several pieces of simple data.

*/

#include "hashpp.h"

using namespace hashpp;

int main() {
	// get a hash collection containing the MD5 and MD4 hashes for all passed data
	std::vector<std::string> data1 = { "data1", "data2", "data3", "data4", "data5", "data6", "data7", "data8", "data9" };
	std::vector<std::string> data2 = { "data1", "data2", "data3", "data4", "data5", "data6", "data7", "data8", "data9" };
	hashCollection collection2 = get::getHashes({ {ALGORITHMS::MD4, data1}, {ALGORITHMS::MD5, data2} });

	// the method above of getting multiple hashes is equivalent to the below
	hashCollection collection = get::getHashes({ {ALGORITHMS::MD4, {"data1", "data2", "data3",
		                                                        "data4", "data5", "data6",
		                                                        "data7", "data8", "data9"} },
						     {ALGORITHMS::MD5, {"data1", "data2", "data3",
					                                "data4", "data5", "data6",
					                                "data7", "data8", "data9"} } }); 
	
	// to iterate over hashes from a specific algorithm (in the order they were supplied)
	for (auto i : collection["MD5"]) {
		std::cout << i << std::endl;
	}
	for (auto i : collection["MD4"]) {
		std::cout << i << std::endl;
	}
	
	// the above will iterate through the hashes of "data1"-"data9" for both MD5 and MD4
	/*
		First iteration (MD5):
			89d903bc35dede724fd52c51437ff5fd
			ff9cf2d690d888cb337f6bf4526b6130
			79369f78f7882c1baabbc7d45dc5daa0
			732160808412a20c3f0bfad2b3822d1b
			cd8e177a28c90b63d548464fa36b2a14
			78c5d69ee9c8aecbf63710a3733501f2
			4a7506e3aa540549299dbf459238f7be
			c1e739549f7045ca51d24faee4d3f18d
			fc5f764fd223e02a85787099f2e51431
		Second Iteration (MD4):
			6ae4b3d10b07413e1ea4915f6da7cab4
			ce730e5c428c5fd0dc951c90508547fe
			a4673b83fec1b1ae9eeea7f22a71f86f
			2985b2773e43dce3033e38eab9956fc5
			6f818b962e62ad9f406e98efbd65feb4
			ecd827c94a72c4e23b7fb39b962ed54a
			81847db91976839c31292c83eac2683d
			496c47c9f969be38672817cac65bb38d
			03ce39fe2914fafebd1bcb81acb816ea
	*/
}
