/*

	Simple program to hash comman-line supplied data
		Example:
			./program.exe data1 data2 data3

			output:
						 MD5: "data1": 89d903bc35dede724fd52c51437ff5fd
						 MD4: "data1": 6ae4b3d10b07413e1ea4915f6da7cab4
						 MD2: "data1": 2feff92dc8130b5f4104e430a77269e0
						SHA1: "data1": cbcc2ff6a0894e6e7f9a1a6a6a36b68fb36aa151
					SHA2-224: "data1": 2fa1977e21efb718f7bfa4392e8ff6f9cd07ef2c81e1f0bd5164f8b7
					SHA2-256: "data1": 5b41362bc82b7f3d56edc5a306db22105707d01ff4819e26faef9724a2d406c9
					SHA2-384: "data1": ea77c52d2aab72be97f2864011b11a2d16b07eb67c9dfb9549ac141e2a03369ac59563f5f370a7504f72bccd0ccad31c
					SHA2-512: "data1": 9731b541b22c1d7042646ab2ee17685bbb664bced666d8ecf3593f3ef46493deef651b0f31b6cff8c4df8dcb425a1035e86ddb9877a8685647f39847be0d7c01
				SHA2-512/224: "data1": 42161d4488f6f3d03e4f05f85d6354ed8f211ebdd563ba928c388010
				SHA2-512/256: "data1": b4b134e80ec4b27a0d5ab88c7c466ddfca17ce9f4b4369f83b118bfea09516c0
					... and so on ...

*/

#include "hashpp.h"

using namespace hashpp;

int main(int argc, const char* argv[]) {
	for (int i = 1; i < argc; i++) {
		std::cout << "         MD5: \"" << argv[i] << "\": " << get::getHash(ALGORITHMS::MD5, argv[i]) << std::endl;
		std::cout << "         MD4: \"" << argv[i] << "\": " << get::getHash(ALGORITHMS::MD4, argv[i]) << std::endl;
		std::cout << "         MD2: \"" << argv[i] << "\": " << get::getHash(ALGORITHMS::MD2, argv[i]) << std::endl;
		std::cout << "        SHA1: \"" << argv[i] << "\": " << get::getHash(ALGORITHMS::SHA1, argv[i]) << std::endl;
		std::cout << "    SHA2-224: \"" << argv[i] << "\": " << get::getHash(ALGORITHMS::SHA2_224, argv[i]) << std::endl;
		std::cout << "    SHA2-256: \"" << argv[i] << "\": " << get::getHash(ALGORITHMS::SHA2_256, argv[i]) << std::endl;
		std::cout << "    SHA2-384: \"" << argv[i] << "\": " << get::getHash(ALGORITHMS::SHA2_384, argv[i]) << std::endl;
		std::cout << "    SHA2-512: \"" << argv[i] << "\": " << get::getHash(ALGORITHMS::SHA2_512, argv[i]) << std::endl;
		std::cout << "SHA2-512/224: \"" << argv[i] << "\": " << get::getHash(ALGORITHMS::SHA2_512_224, argv[i]) << std::endl;
		std::cout << "SHA2-512/256: \"" << argv[i] << "\": " << get::getHash(ALGORITHMS::SHA2_512_256, argv[i]) << std::endl;
	}
}
