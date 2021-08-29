/*
* 
  getHashesFromFiles:
		Example to show how to get the hashes of multiple files in a directory
		or nested directory.

		Assume relative path used has structure:
		 .
		 |--> /folder1
			 |--> /folder2
				 |--  item6.txt
                         |--  item1.txt
		         |--  item2.txt
		         |--  item3.txt
		         |--  item4.txt
		         |--  item5.txt

		hashpp::get::getFilesHashes() traverses directories and hashes files
		alphabetically.

*/

#include "hashpp.h"

using namespace hashpp;

int main() {
	// get a collection of hashes in the directory ./folder1
	hashCollection _a = get::getFilesHashes({ {ALGORITHMS::MD5, {"./folder1"}} });

	// print each MD5 hash collected
	for (auto _z : _a["MD5"]) {
		std::cout << _z << std::endl;
	}

	/* the output is as follows:
			11ddbaf3386aea1f2974eee984542152 -> ./folder1/folder2/item6.txt
			4817a091b69d5e89d7d5757e6ce19609 -> ./folder1/item1.txt
			15cd0e3d368b6a8eb7378dc81ad40dfb -> ./folder1/item2.txt
			e09ab0e2ff8e94687f228eac8a627887 -> ./folder1/item3.txt
			2995ff3cd4c7d15b529bf3fa76e5cc71 -> ./folder1/item4.txt
			8188577c8d593f7654c3cc621fdfa009 -> ./folder1/item5.txt
	*/
}
