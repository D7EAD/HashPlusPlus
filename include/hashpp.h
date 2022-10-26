#ifndef HASHPP_H
#define HASHPP_H

/*

	Copyright (c) 2012-2021 Scott Chacon and others

	Permission is hereby granted, free of charge, to any person obtaining
	a copy of this software and associated documentation files (the
	"Software"), to deal in the Software without restriction, including
	without limitation the rights to use, copy, modify, merge, publish,
	distribute, sublicense, and/or sell copies of the Software, and to
	permit persons to whom the Software is furnished to do so, subject to
	the following conditions:

	The above copyright notice and this permission notice shall be
	included in all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
	EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
	MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
	NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
	LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
	OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
	WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

	----------------------------------------------------------------------

	hash++ : header-only hash implementations in C++
		 This header file contains implementations of Message Digest
		 and Secure Hash Algorithm family hash algorithms for others
		 to view internal mechanisms of said algorithms, as well as
		 for substitution in sources absent the need for heavier
		 crypto-related libraries such as OpenSSL or Crypto++.

*/

#define GU64B(x, y, z) do {		           \
	(x) = ( ((uint64_t) (y)[(z)]) << 56 )	   \
	| ( ((uint64_t) (y)[(z) + 1]) << 48 )	   \
	| ( ((uint64_t) (y)[(z) + 2]) << 40 )	   \
	| ( ((uint64_t) (y)[(z) + 3]) << 32 )	   \
	| ( ((uint64_t) (y)[(z) + 4]) << 24 )	   \
	| ( ((uint64_t) (y)[(z) + 5]) << 16 )	   \
	| ( ((uint64_t) (y)[(z) + 6]) <<  8 )	   \
	| ( ((uint64_t) (y)[(z) + 7])	    );	   \
} while(0)					   \

#define PU64B(x, y, z) do {			   \
	(y)[(z)    ] = (uint8_t) ( (x) >> 56 );	   \
	(y)[(z) + 1] = (uint8_t) ( (x) >> 48 );	   \
	(y)[(z) + 2] = (uint8_t) ( (x) >> 40 );	   \
	(y)[(z) + 3] = (uint8_t) ( (x) >> 32 );	   \
	(y)[(z) + 4] = (uint8_t) ( (x) >> 24 );	   \
	(y)[(z) + 5] = (uint8_t) ( (x) >> 16 );	   \
	(y)[(z) + 6] = (uint8_t) ( (x) >>  8 );	   \
	(y)[(z) + 7] = (uint8_t) ( (x)       );	   \
} while(0)					   \

#define PU128B(l,h,y,z) do {		 	   \
	PU64B(((l) >> 61) ^ ((h) << 3), (y), (z)); \
	PU64B(((l) << 3), (y), (z) + 8);           \
} while(0)					   \

#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <memory>
#include <array>
#include <vector>

namespace hashpp {
	enum class ALGORITHMS : uint8_t {
		// MDX Family
		MD5, MD4, MD2,

		// SHA-X Family
		SHA1, SHA2_224, SHA2_256,
		SHA2_384, SHA2_512, SHA2_512_224,
		SHA2_512_256 /*, SHA3_224, SHA3_256,
		SHA3_384, SHA3_512, SHAKE128,
		SHAKE256 */
	};

	// class containing common data and methods to be
	// derived from by algorithm classes for common use
	// internally
	class common {
	public:
		// helper functions to rotate left
		uint32_t rl32(uint32_t x, uint32_t y) noexcept {
			return (x << y) | (x >> (32 - y));
		}
		uint64_t rl64(uint64_t x, uint64_t y) noexcept {
			return (x << y) | (x >> (64 - y));
		}

		// helper functions to rotate right
		uint32_t rr32(uint32_t x, uint32_t y) noexcept {
			return (x >> y) | (x << (32 - y));
		}
		uint64_t rr64(uint64_t x, uint64_t y) noexcept {
			return (x >> y) | (x << (64 - y));
		}

		// hex table for converting bytes to representable
		// hexadecimal strings for output via getHash
		const std::array<const char*, 256> hexTable{
			"00", "01", "02", "03", "04", "05", "06", "07",
			"08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
			"10", "11", "12", "13", "14", "15", "16", "17",
			"18", "19", "1a", "1b", "1c", "1d", "1e", "1f",
			"20", "21", "22", "23", "24", "25", "26", "27",
			"28", "29", "2a", "2b", "2c", "2d", "2e", "2f",
			"30", "31", "32", "33", "34", "35", "36", "37",
			"38", "39", "3a", "3b", "3c", "3d", "3e", "3f",
			"40", "41", "42", "43", "44", "45", "46", "47",
			"48", "49", "4a", "4b", "4c", "4d", "4e", "4f",
			"50", "51", "52", "53", "54", "55", "56", "57",
			"58", "59", "5a", "5b", "5c", "5d", "5e", "5f",
			"60", "61", "62", "63", "64", "65", "66", "67",
			"68", "69", "6a", "6b", "6c", "6d", "6e", "6f",
			"70", "71", "72", "73", "74", "75", "76", "77",
			"78", "79", "7a", "7b", "7c", "7d", "7e", "7f",
			"80", "81", "82", "83", "84", "85", "86", "87",
			"88", "89", "8a", "8b", "8c", "8d", "8e", "8f",
			"90", "91", "92", "93", "94", "95", "96", "97",
			"98", "99", "9a", "9b", "9c", "9d", "9e", "9f",
			"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
			"a8", "a9", "aa", "ab", "ac", "ad", "ae", "af",
			"b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7",
			"b8", "b9", "ba", "bb", "bc", "bd", "be", "bf",
			"c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7",
			"c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf",
			"d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
			"d8", "d9", "da", "db", "dc", "dd", "de", "df",
			"e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7",
			"e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef",
			"f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7",
			"f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff"
		};

		// get hexadecimal hash from supplied string data
		std::string getHash(const std::string& data) {
			ctx_init();
			ctx_update(reinterpret_cast<uint8_t*>(const_cast<char*>(data.c_str())), data.length());
			ctx_final();
			return getHashStr();
		}

		// get hexadecimal hash from file
		std::string getHash(const std::filesystem::path& path) {
			this->ctx_init();
			{
				std::ifstream file(path, std::ios::binary);
				std::vector<char> buf(1024 * 1024, 0);
				while (!file.eof()) {
					file.read(buf.data(), buf.size());
					this->ctx_update(reinterpret_cast<uint8_t*>(buf.data()), file.gcount());
				}
			}
			this->ctx_final();
			return getHashStr();
		}

	protected:
		// virtual functions that must be defined by hashers
		virtual std::vector<uint8_t> getDigest() = 0;
	  virtual void ctx_init() = 0;
		virtual void ctx_update(const uint8_t* data, size_t len) = 0;
		virtual void ctx_final() = 0;

	private:
		// convert hash from binary to string
		std::string getHashStr() {
			const std::vector<uint8_t>& digest = getDigest();
			std::string hash;
			for (const auto& d : digest)
				hash += this->hexTable[d];
			return hash;
		}
	};

	// Message Digest (MDX) hash family - excluding MD6
	namespace MD {
		class MD5 : public common {
		protected:
			std::vector<uint8_t> getDigest() override {
				return std::vector<uint8_t>(context.digest, context.digest + 16);
			}
		private:
			typedef struct {
				uint64_t size;
				uint32_t buf[4];
				uint8_t  in[64], digest[16];
			} CTX;

			// CTX context instance
			CTX context = { 0 };

			// per-round shift amounts
			// as per: https://en.wikipedia.org/wiki/MD5#Pseudocode
			const std::array<uint8_t, 64> S{
				7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
				5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
				4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
				6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
			};

			// as per: https://en.wikipedia.org/wiki/MD5#Pseudocode
			const std::array<uint32_t, 64> K{
				0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
				0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
				0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
				0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
				0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
				0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
				0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
				0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
			};

			// pad data for when we need to... well.. pad to appropriate size
			std::array<uint8_t, 64> pad{
				0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
			};

			// MD5 algorithm-defined constants 
			// as per: https://en.wikipedia.org/wiki/MD5#Pseudocode
			const uint32_t A = 0x67452301;
			const uint32_t B = 0xefcdab89;
			const uint32_t C = 0x98badcfe;
			const uint32_t D = 0x10325476;

			// private class methods
		private:
			// initialize our context for this hash function
			void ctx_init() override;
			void ctx_transform(const uint32_t* data);
			void ctx_update(const uint8_t* data, size_t len) override;
			void ctx_final() override;

			// auxiliary functions defined by the algorithm
			// as per: https://en.wikipedia.org/wiki/MD5#Algorithm
			constexpr uint32_t F(const uint32_t B, const uint32_t C, const uint32_t D);
			constexpr uint32_t G(const uint32_t B, const uint32_t C, const uint32_t D);
			constexpr uint32_t H(const uint32_t B, const uint32_t C, const uint32_t D);
			constexpr uint32_t I(const uint32_t B, const uint32_t C, const uint32_t D);
		};
		class MD4 : public common {
		protected:
			std::vector<uint8_t> getDigest() override {
				return std::vector<uint8_t>(context.digest, context.digest + 16);
			}
		private:
			typedef struct {
				uint64_t size;
				uint32_t buf[4];
				uint8_t  in[64], digest[16];
			} CTX;

			// CTX context instance
			CTX context = { 0 };

			const std::array<uint8_t, 64> S{
				7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
				5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
				4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
				6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
			};

			const std::array<uint32_t, 64> K{
				0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
				0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
				0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
				0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
				0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
				0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
				0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
				0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
			};

			// pad data for when we need to... well.. pad to appropriate size
			std::array<uint8_t, 64> pad{
				0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
			};

			// algorithm-defined constants
			const uint32_t A = 0x67452301;
			const uint32_t B = 0xefcdab89;
			const uint32_t C = 0x98badcfe;
			const uint32_t D = 0x10325476;

			// private class methods
		private:
			// initialize our context for this hash function
			void ctx_init() override;
			void ctx_transform(const uint32_t* data);
			void ctx_update(const uint8_t* data, size_t len) override;
			void ctx_final() override;

			// auxiliary functions defined by the algorithm
			// as per: http://practicalcryptography.com/hashes/md4-hash/
			constexpr uint32_t F(const uint32_t B, const uint32_t C, const uint32_t D);
			constexpr uint32_t G(const uint32_t B, const uint32_t C, const uint32_t D);
			constexpr uint32_t H(const uint32_t B, const uint32_t C, const uint32_t D);

			// round functions
			void R1(uint32_t& a, const uint32_t b, const uint32_t c, const uint32_t d, const uint32_t k, const uint32_t s);
			void R2(uint32_t& a, const uint32_t b, const uint32_t c, const uint32_t d, const uint32_t k, const uint32_t s);
			void R3(uint32_t& a, const uint32_t b, const uint32_t c, const uint32_t d, const uint32_t k, const uint32_t s);
		};
		class MD2 : public common {
		protected:
			std::vector<uint8_t> getDigest() override {
				return std::vector<uint8_t>(context.digest, context.digest + 16);
			}
		private:
			typedef struct {
				uint8_t buf[16], state[48], checksum[16], digest[16];
				uint64_t size;
			} CTX;

			CTX context = { 0 };

			// S-table values for MD2 algorithm 
			// as per: https://en.wikipedia.org/wiki/MD2_(hash_function)#Description
			const std::array<uint8_t, 256> S{
				0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01, 0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13,
				0x62, 0xA7, 0x05, 0xF3, 0xC0, 0xC7, 0x73, 0x8C, 0x98, 0x93, 0x2B, 0xD9, 0xBC, 0x4C, 0x82, 0xCA,
				0x1E, 0x9B, 0x57, 0x3C, 0xFD, 0xD4, 0xE0, 0x16, 0x67, 0x42, 0x6F, 0x18, 0x8A, 0x17, 0xE5, 0x12,
				0xBE, 0x4E, 0xC4, 0xD6, 0xDA, 0x9E, 0xDE, 0x49, 0xA0, 0xFB, 0xF5, 0x8E, 0xBB, 0x2F, 0xEE, 0x7A,
				0xA9, 0x68, 0x79, 0x91, 0x15, 0xB2, 0x07, 0x3F, 0x94, 0xC2, 0x10, 0x89, 0x0B, 0x22, 0x5F, 0x21,
				0x80, 0x7F, 0x5D, 0x9A, 0x5A, 0x90, 0x32, 0x27, 0x35, 0x3E, 0xCC, 0xE7, 0xBF, 0xF7, 0x97, 0x03,
				0xFF, 0x19, 0x30, 0xB3, 0x48, 0xA5, 0xB5, 0xD1, 0xD7, 0x5E, 0x92, 0x2A, 0xAC, 0x56, 0xAA, 0xC6,
				0x4F, 0xB8, 0x38, 0xD2, 0x96, 0xA4, 0x7D, 0xB6, 0x76, 0xFC, 0x6B, 0xE2, 0x9C, 0x74, 0x04, 0xF1,
				0x45, 0x9D, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20, 0x86, 0x5B, 0xCF, 0x65, 0xE6, 0x2D, 0xA8, 0x02,
				0x1B, 0x60, 0x25, 0xAD, 0xAE, 0xB0, 0xB9, 0xF6, 0x1C, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7E, 0x0F,
				0x55, 0x47, 0xA3, 0x23, 0xDD, 0x51, 0xAF, 0x3A, 0xC3, 0x5C, 0xF9, 0xCE, 0xBA, 0xC5, 0xEA, 0x26,
				0x2C, 0x53, 0x0D, 0x6E, 0x85, 0x28, 0x84, 0x09, 0xD3, 0xDF, 0xCD, 0xF4, 0x41, 0x81, 0x4D, 0x52,
				0x6A, 0xDC, 0x37, 0xC8, 0x6C, 0xC1, 0xAB, 0xFA, 0x24, 0xE1, 0x7B, 0x08, 0x0C, 0xBD, 0xB1, 0x4A,
				0x78, 0x88, 0x95, 0x8B, 0xE3, 0x63, 0xE8, 0x6D, 0xE9, 0xCB, 0xD5, 0xFE, 0x3B, 0x00, 0x1D, 0x39,
				0xF2, 0xEF, 0xB7, 0x0E, 0x66, 0x58, 0xD0, 0xE4, 0xA6, 0x77, 0x72, 0xF8, 0xEB, 0x75, 0x4B, 0x0A,
				0x31, 0x44, 0x50, 0xB4, 0x8F, 0xED, 0x1F, 0x1A, 0xDB, 0x99, 0x8D, 0x33, 0x9F, 0x11, 0x83, 0x14
			};

			void ctx_init() override;
			void ctx_transform(const uint8_t* data);
			void ctx_update(const uint8_t* data, size_t len) override;
			void ctx_final() override;
		};

		// MD5
		void hashpp::MD::MD5::ctx_init() {
			this->context = {
				0,
				{this->A, this->B, this->C, this->D}				
			};
		}
		void hashpp::MD::MD5::ctx_transform(const uint32_t* data) {
			std::array<uint32_t, 4> results{
				this->context.buf[0], // a0
				this->context.buf[1], // b0
				this->context.buf[2], // c0
				this->context.buf[3]  // d0
			};

			uint32_t E, j, t;
			for (uint32_t i = 0; i < 64; ++i) {
				switch (i / 16) {
				case 0: {
					E = this->F(results[1], results[2], results[3]);
					j = i;
					break;
				}
				case 1: {
					E = this->G(results[1], results[2], results[3]);
					j = ((i * 5) + 1) % 16;
					break;
				}
				case 2: {
					E = this->H(results[1], results[2], results[3]);
					j = ((i * 3) + 5) % 16;
					break;
				}
				default: {
					E = this->I(results[1], results[2], results[3]);
					j = (i * 7) % 16;
					break;
				}
				}

				t = results[3];
				results[3] = results[2]; results[2] = results[1];
				results[1] = results[1] + this->rl32(results[0] + E + K[i] + data[j], S[i]);
				results[0] = t;
			}

			for (uint32_t z = 0; z < 4; z++) {
				this->context.buf[z] += results[z];
			}
		}
		void hashpp::MD::MD5::ctx_update(const uint8_t* data, size_t len) {
			uint32_t input[16], offset = this->context.size % 64;
			this->context.size += static_cast<uint64_t>(len);

			for (uint32_t i = 0; i < len; ++i) {
				this->context.in[offset++] = static_cast<uint8_t>(*(data + i));

				if (offset % 64 == 0) {
					for (uint32_t j = 0; j < 16; ++j) {
						input[j] = static_cast<uint32_t>(this->context.in[(j * 4) + 3]) << 24 |
							static_cast<uint32_t>(this->context.in[(j * 4) + 2]) << 16 |
							static_cast<uint32_t>(this->context.in[(j * 4) + 1]) << 8 |
							static_cast<uint32_t>(this->context.in[(j * 4)]);
					}
					this->ctx_transform(input);
					offset = 0;
				}
			}
		}
		void hashpp::MD::MD5::ctx_final() {
			uint32_t input[16];
			uint32_t offset = this->context.size % 64;
			uint32_t plen = offset < 56 ? 56 - offset : (56 + 64) - offset;

			this->ctx_update(this->pad._Elems, plen);
			this->context.size -= static_cast<uint64_t>(plen);

			for (uint32_t j = 0; j < 14; ++j) {
				input[j] = static_cast<uint32_t>(this->context.in[(j * 4) + 3]) << 24 |
					static_cast<uint32_t>(this->context.in[(j * 4) + 2]) << 16 |
					static_cast<uint32_t>(this->context.in[(j * 4) + 1]) << 8 |
					static_cast<uint32_t>(this->context.in[(j * 4)]);
			}
			input[14] = static_cast<uint32_t>(this->context.size * 8);
			input[15] = static_cast<uint32_t>((this->context.size * 8) >> 32);

			this->ctx_transform(input);

			for (uint32_t i = 0; i < 4; ++i) {
				this->context.digest[(i * 4) + 0] = static_cast<uint8_t>((this->context.buf[i] & 0x000000FF));
				this->context.digest[(i * 4) + 1] = static_cast<uint8_t>((this->context.buf[i] & 0x0000FF00) >> 8);
				this->context.digest[(i * 4) + 2] = static_cast<uint8_t>((this->context.buf[i] & 0x00FF0000) >> 16);
				this->context.digest[(i * 4) + 3] = static_cast<uint8_t>((this->context.buf[i] & 0xFF000000) >> 24);
			}
		}
		constexpr uint32_t hashpp::MD::MD5::F(const uint32_t B, const uint32_t C, const uint32_t D) { return ((B & C) | (~B & D)); }
		constexpr uint32_t hashpp::MD::MD5::G(const uint32_t B, const uint32_t C, const uint32_t D) { return ((B & D) | (C & ~D)); }
		constexpr uint32_t hashpp::MD::MD5::H(const uint32_t B, const uint32_t C, const uint32_t D) { return ((B ^ C ^ D)); }
		constexpr uint32_t hashpp::MD::MD5::I(const uint32_t B, const uint32_t C, const uint32_t D) { return (C ^ (B | ~D)); }

		// MD4
		void hashpp::MD::MD4::ctx_init() {
			this->context = {
				0,
				{this->A, this->B, this->C, this->D}
			};
		}
		void hashpp::MD::MD4::ctx_transform(const uint32_t* data) {
			std::array<uint32_t, 4> results{
				this->context.buf[0], // a0
				this->context.buf[1], // b0
				this->context.buf[2], // c0
				this->context.buf[3]  // d0
			};

			// perform rounds as described by the algorithm
			// as per: http://practicalcryptography.com/hashes/md4-hash/
			for (uint32_t i = 0, j = 0; i < 4; ++i, j += 4) {
				this->R1(results[0], results[1], results[2], results[3], data[j], 3);
				this->R1(results[3], results[0], results[1], results[2], data[j + 1], 7);
				this->R1(results[2], results[3], results[0], results[1], data[j + 2], 11);
				this->R1(results[1], results[2], results[3], results[0], data[j + 3], 19);
			}

			for (uint32_t i = 0; i < 4; ++i) {
				this->R2(results[0], results[1], results[2], results[3], data[0 + i], 3);
				this->R2(results[3], results[0], results[1], results[2], data[4 + i], 5);
				this->R2(results[2], results[3], results[0], results[1], data[8 + i], 9);
				this->R2(results[1], results[2], results[3], results[0], data[12 + i], 13);
			}

			for (uint32_t i = 0, _h = 0; i < 4; ++i) {
				i == 1 ? _h = 2 : 0; i == 2 ? _h = 1 : 0; i == 3 ? _h = 3 : 0;
				this->R3(results[0], results[1], results[2], results[3], data[0 + _h], 3);
				this->R3(results[3], results[0], results[1], results[2], data[8 + _h], 9);
				this->R3(results[2], results[3], results[0], results[1], data[4 + _h], 11);
				this->R3(results[1], results[2], results[3], results[0], data[12 + _h], 15);
			}

			for (uint32_t z = 0; z < 4; z++) {
				this->context.buf[z] += results[z];
			}
		}
		void hashpp::MD::MD4::ctx_update(const uint8_t* data, size_t len) {
			uint32_t input[16], offset = this->context.size % 64;
			this->context.size += static_cast<uint64_t>(len);

			for (uint32_t i = 0; i < len; ++i) {
				this->context.in[offset++] = static_cast<uint8_t>(*(data + i));

				if (offset % 64 == 0) {
					for (uint32_t j = 0; j < 16; ++j) {
						input[j] = static_cast<uint32_t>(this->context.in[(j * 4) + 3]) << 24 |
							static_cast<uint32_t>(this->context.in[(j * 4) + 2]) << 16 |
							static_cast<uint32_t>(this->context.in[(j * 4) + 1]) << 8 |
							static_cast<uint32_t>(this->context.in[(j * 4)]);
					}
					this->ctx_transform(input);
					offset = 0;
				}
			}
		}
		void hashpp::MD::MD4::ctx_final() {
			uint32_t input[16];
			uint32_t offset = this->context.size % 64, plen = offset < 56 ? 56 - offset : (56 + 64) - offset;

			this->ctx_update(this->pad._Elems, plen);
			this->context.size -= static_cast<uint64_t>(plen);

			for (uint32_t j = 0; j < 14; ++j) {
				input[j] = static_cast<uint32_t>(this->context.in[(j * 4) + 3]) << 24 |
					static_cast<uint32_t>(this->context.in[(j * 4) + 2]) << 16 |
					static_cast<uint32_t>(this->context.in[(j * 4) + 1]) << 8 |
					static_cast<uint32_t>(this->context.in[(j * 4)]);
			}
			input[14] = static_cast<uint32_t>(this->context.size * 8);
			input[15] = static_cast<uint32_t>((this->context.size * 8) >> 32);

			this->ctx_transform(input);

			// move to digest as big-endian
			// as per: https://stackoverflow.com/questions/19275955/convert-little-endian-to-big-endian/19276193
			for (uint32_t i = 0; i < 4; ++i) {
				this->context.digest[(i * 4) + 0] = static_cast<uint8_t>((this->context.buf[i] & 0x000000FF));
				this->context.digest[(i * 4) + 1] = static_cast<uint8_t>((this->context.buf[i] & 0x0000FF00) >> 8);
				this->context.digest[(i * 4) + 2] = static_cast<uint8_t>((this->context.buf[i] & 0x00FF0000) >> 16);
				this->context.digest[(i * 4) + 3] = static_cast<uint8_t>((this->context.buf[i] & 0xFF000000) >> 24);
			}
		}
		constexpr uint32_t hashpp::MD::MD4::F(const uint32_t B, const uint32_t C, const uint32_t D) { return ((B & C) | (~B & D)); }
		constexpr uint32_t hashpp::MD::MD4::G(const uint32_t B, const uint32_t C, const uint32_t D) { return ((B & C) | (B & D) | (C & D)); }
		constexpr uint32_t hashpp::MD::MD4::H(const uint32_t B, const uint32_t C, const uint32_t D) { return ((B ^ C ^ D)); }
		void hashpp::MD::MD4::R1(uint32_t& a, const uint32_t b, const uint32_t c, const uint32_t d, const uint32_t k, const uint32_t s) {
			a = this->rl32(a + this->F(b, c, d) + k, s);
		}
		void hashpp::MD::MD4::R2(uint32_t& a, const uint32_t b, const uint32_t c, const uint32_t d, const uint32_t k, const uint32_t s) {
			a = this->rl32(a + this->G(b, c, d) + k + static_cast<uint32_t>(0x5A827999), s);
		}
		void hashpp::MD::MD4::R3(uint32_t& a, const uint32_t b, const uint32_t c, const uint32_t d, const uint32_t k, const uint32_t s) {
			a = this->rl32(a + this->H(b, c, d) + k + static_cast<uint32_t>(0x6ED9EBA1), s);
		}

		// MD2
		void hashpp::MD::MD2::ctx_init() {
			memset(this->context.state, 0, 48);
			memset(this->context.checksum, 0, 16);
			memset(this->context.buf, 0, 16);
			memset(this->context.digest, 0, 16);
			this->context.size = 0;
		}
		void hashpp::MD::MD2::ctx_transform(const uint8_t* data) {
			uint32_t j, k, t;

			for (j = 0; j < 16; ++j) {
				this->context.state[j + 16] = data[j];
				this->context.state[j + 32] = (this->context.state[j + 16] ^ this->context.state[j]);
			}

			t = 0;
			for (j = 0; j < 18; ++j) {
				for (k = 0; k < 48; ++k) {
					this->context.state[k] ^= this->S[t];
					t = this->context.state[k];
				}
				t = (t + j) & 0xFF;
			}

			t = this->context.checksum[15];
			for (j = 0; j < 16; ++j) {
				this->context.checksum[j] ^= this->S[data[j] ^ t];
				t = this->context.checksum[j];
			}
		}
		void hashpp::MD::MD2::ctx_update(const uint8_t* data, size_t len) {
			for (uint16_t i = 0; i < len; ++i) {
				this->context.buf[this->context.size] = data[i];
				this->context.size++;
				if (this->context.size == 16) {
					ctx_transform(this->context.buf);
					this->context.size = 0;
				}
			}
		}
		void hashpp::MD::MD2::ctx_final() {
			uint32_t pad = 16 - this->context.size;
			while (this->context.size < 16) {
				this->context.buf[this->context.size++] = pad;
			}
			ctx_transform(this->context.buf);
			ctx_transform(this->context.checksum);
			memcpy(this->context.digest, this->context.state, 16);
		}
	}

	// Secure Hash Algorithm (SHA) hash family 
	namespace SHA {
		// SHA algorithms, such as SHA2-224, SHA2-384,
		// SHA2-512-224, and SHA2-512-256 are simply
		// truncated versions of their accompanying
		// algorithm.
		//
		// for instance, SHA2-512-256 is SHA-512
		// truncated to a 256-bit digest length.
		// likewise, SHA2-224 is SHA2-256 truncated
		// to a 224-bit digest length.
		//
		// these truncations are achieved via the 
		// omission of trailing H-constants from
		// the digest output, as well as different
		// H-constant values from the orignal
		// algorithm.

		class SHA1 : public common {
		protected:
			std::vector<uint8_t> getDigest() override {
				return std::vector<uint8_t>(context.digest, context.digest + 20);
			}
		private:
			typedef struct {
				uint32_t state[5], k[4], size;
				uint64_t bitsize;
				uint8_t  data[64], digest[20];
			} CTX;

			CTX context = { 0 };

			// constants (H) defined by SHA-1 algorithm
			// as per: https://datatracker.ietf.org/doc/html/rfc3174
			const std::array<uint32_t, 5> H{
				0x67452301,
				0xEFCDAB89,
				0x98BADCFE,
				0x10325476,
				0xc3d2e1f0
			};

			// more constants (K)... as per above
			const std::array<uint32_t, 4> K{
				0x5a827999,
				0x6ed9eba1,
				0x8f1bbcdc,
				0xca62c1d6
			};

			void ctx_init() override;
			void ctx_transform(const uint8_t* data);
			void ctx_update(const uint8_t* data, size_t len) override;
			void ctx_final() override;

			// SHA-1 functions defined by the algorithm
			constexpr uint32_t A(const uint32_t A, const uint32_t B, const uint32_t C, const uint32_t D);
			constexpr uint32_t B(const uint32_t A, const uint32_t B, const uint32_t C, const uint32_t D);
			constexpr uint32_t C(const uint32_t A);

			// ...and more defined functions...
			constexpr uint32_t F(const uint32_t B, const uint32_t C, const uint32_t D);
			constexpr uint32_t G(const uint32_t B, const uint32_t C, const uint32_t D);
			constexpr uint32_t J(const uint32_t B, const uint32_t C, const uint32_t D);
		};
		class SHA2_224 : public common {
		protected:
			std::vector<uint8_t> getDigest() override {
				return std::vector<uint8_t>(context.digest, context.digest + 28);
			}
		private:
			typedef struct {
				uint32_t state[8];
				uint64_t size, bitsize;
				uint8_t  data[64], digest[28];
			} CTX;

			CTX context = { 0 };

			// constants (H) defined by SHA2-224 algorithm
			// as per: https://datatracker.ietf.org/doc/html/rfc3874
			const std::array<uint32_t, 8> H{
				0xC1059ED8,
				0x367CD507,
				0x3070DD17,
				0xF70E5939,
				0xFFC00B31,
				0x68581511,
				0x64F98FA7,
				0xBEFA4FA4
			};

			// more constants (K)... as per above
			const std::array<uint32_t, 64> K{
				0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
				0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
				0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
				0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
				0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
				0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
				0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
				0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
				0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
				0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
				0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
				0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
				0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
				0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
				0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
				0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
			};

			void ctx_init() override;
			void ctx_transform(const uint8_t* data);
			void ctx_update(const uint8_t* data, size_t len) override;
			void ctx_final() override;

			constexpr uint32_t A(const uint32_t A, const uint32_t B, const uint32_t C, const uint32_t D);
			constexpr uint32_t F(const uint32_t B, const uint32_t C, const uint32_t D);
			constexpr uint32_t G(const uint32_t B, const uint32_t C, const uint32_t D);

			// Sigma functions
			// as per: https://datatracker.ietf.org/doc/html/rfc6234
			uint32_t SIGMA0(const uint32_t A);
			uint32_t SIGMA1(const uint32_t A);
			uint32_t SIGMA2(const uint32_t A);
			uint32_t SIGMA3(const uint32_t A);
		};
		class SHA2_256 : public common {
		protected:
			std::vector<uint8_t> getDigest() override {
				return std::vector<uint8_t>(context.digest, context.digest + 32);
			}
		private:
			typedef struct {
				uint32_t state[8], size;
				uint64_t bitsize;
				uint8_t  data[64], digest[32];
			} CTX;

			CTX context = { 0 };

			// constants (H) defined by SHA-256 algorithm
			// as per: https://datatracker.ietf.org/doc/html/rfc6234
			const std::array<uint32_t, 8> H{
				0x6a09e667,
				0xbb67ae85,
				0x3c6ef372,
				0xa54ff53a,
				0x510e527f,
				0x9b05688c,
				0x1f83d9ab,
				0x5be0cd19
			};

			// more constants (K)... as per above
			const std::array<uint32_t, 64> K{
				0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
				0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
				0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
				0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
				0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
				0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
				0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
				0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
				0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
				0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
				0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
				0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
				0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
				0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
				0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
				0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
			};

			void ctx_init() override;
			void ctx_transform(const uint8_t* data);
			void ctx_update(const uint8_t* data, size_t len) override;
			void ctx_final() override;

			constexpr uint32_t A(const uint32_t A, const uint32_t B, const uint32_t C, const uint32_t D);
			constexpr uint32_t F(const uint32_t B, const uint32_t C, const uint32_t D);
			constexpr uint32_t G(const uint32_t B, const uint32_t C, const uint32_t D);

			// Sigma functions
			// as per: https://datatracker.ietf.org/doc/html/rfc6234
			uint32_t SIGMA0(const uint32_t A);
			uint32_t SIGMA1(const uint32_t A);
			uint32_t SIGMA2(const uint32_t A);
			uint32_t SIGMA3(const uint32_t A);
		};
		class SHA2_384 : public common {
		protected:
			std::vector<uint8_t> getDigest() override {
				return std::vector<uint8_t>(context.digest, context.digest + 48);
			}
		private:
			typedef struct {
				uint64_t state[8], count[2];
				uint8_t  data[128], digest[48];
			} CTX;

			CTX context = { 0 };

			// constants (H) defined by SHA-512 algorithm
			// as per: https://datatracker.ietf.org/doc/html/rfc4634
			const std::array<uint64_t, 8> H{
				0xCBBB9D5DC1059ED8,
				0x629A292A367CD507,
				0x9159015A3070DD17,
				0x152FECD8F70E5939,
				0x67332667FFC00B31,
				0x8EB44A8768581511,
				0xDB0C2E0D64F98FA7,
				0x47B5481DBEFA4FA4
			};

			// more constants (K)... as per above
			const std::array<uint64_t, 80> K{
				0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
				0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
				0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
				0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
				0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
				0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
				0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
				0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
				0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
				0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
				0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
				0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
				0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
				0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
				0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
				0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
				0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
				0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
				0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
				0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
			};

			void ctx_init() override;
			void ctx_transform(const uint8_t* data);
			void ctx_update(const uint8_t* data, size_t len) override;
			void ctx_final() override;

			constexpr uint64_t F(const uint64_t A, const uint64_t B, const uint64_t C);
			constexpr uint64_t G(const uint64_t A, const uint64_t B, const uint64_t C);

			// Sigma functions
			// as per: https://datatracker.ietf.org/doc/html/rfc4634
			uint64_t SIGMA0(const uint64_t A);
			uint64_t SIGMA1(const uint64_t A);
			uint64_t SIGMA2(const uint64_t A);
			uint64_t SIGMA3(const uint64_t A);
		};
		class SHA2_512 : public common {
		protected:
			std::vector<uint8_t> getDigest() override {
				return std::vector<uint8_t>(context.digest, context.digest + 64);
			}
		private:
			typedef struct {
				uint64_t state[8], count[2];
				uint8_t  data[128], digest[64];
			} CTX;

			CTX context = { 0 };

			// constants (H) defined by SHA-512 algorithm
			// as per: https://datatracker.ietf.org/doc/html/rfc4634
			const std::array<uint64_t, 8> H{
				0x6A09E667F3BCC908,
				0xBB67AE8584CAA73B,
				0x3C6EF372FE94F82B,
				0xA54FF53A5F1D36F1,
				0x510E527FADE682D1,
				0x9B05688C2B3E6C1F,
				0x1F83D9ABFB41BD6B,
				0x5BE0CD19137E2179
			};

			// more constants (K)... as per above
			const std::array<uint64_t, 80> K{
				0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
				0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
				0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
				0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
				0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
				0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
				0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
				0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
				0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
				0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
				0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
				0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
				0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
				0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
				0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
				0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
				0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
				0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
				0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
				0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
			};

			void ctx_init() override;
			void ctx_transform(const uint8_t* data);
			void ctx_update(const uint8_t* data, size_t len) override;
			void ctx_final() override;

			constexpr uint64_t F(const uint64_t A, const uint64_t B, const uint64_t C);
			constexpr uint64_t G(const uint64_t A, const uint64_t B, const uint64_t C);

			// Sigma functions
			// as per: https://datatracker.ietf.org/doc/html/rfc4634
			uint64_t SIGMA0(const uint64_t A);
			uint64_t SIGMA1(const uint64_t A);
			uint64_t SIGMA2(const uint64_t A);
			uint64_t SIGMA3(const uint64_t A);
		};
		class SHA2_512_224 : public common {
		protected:
			std::vector<uint8_t> getDigest() override {
				return std::vector<uint8_t>(context.digest, context.digest + 32);
			}
		private:
			typedef struct {
				uint64_t state[8], count[2];
				uint8_t  data[128], digest[32];
			} CTX;

			CTX context = { 0 };

			// constants (H) defined by SHA-512/224 algorithm
			// as per: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_224.pdf
			const std::array<uint64_t, 8> H{
				0x8C3D37C819544DA2,
				0x73E1996689DCD4D6,
				0x1DFAB7AE32FF9C82,
				0x679DD514582F9FCF,
				0x0F6D2B697BD44DA8,
				0x77E36F7304C48942,
				0x3F9D85A86A1D36C8,
				0x1112E6AD91D692A1,
			};

			// more constants (K)... as per above
			const std::array<uint64_t, 80> K{
				0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
				0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
				0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
				0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
				0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
				0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
				0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
				0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
				0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
				0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
				0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
				0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
				0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
				0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
				0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
				0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
				0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
				0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
				0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
				0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
			};

			void ctx_init() override;
			void ctx_transform(const uint8_t* data);
			void ctx_update(const uint8_t* data, size_t len) override;
			void ctx_final() override;

			constexpr uint64_t F(const uint64_t A, const uint64_t B, const uint64_t C);
			constexpr uint64_t G(const uint64_t A, const uint64_t B, const uint64_t C);

			// Sigma functions
			// as per: https://datatracker.ietf.org/doc/html/rfc4634
			uint64_t SIGMA0(const uint64_t A);
			uint64_t SIGMA1(const uint64_t A);
			uint64_t SIGMA2(const uint64_t A);
			uint64_t SIGMA3(const uint64_t A);
		};
		class SHA2_512_256 : public common {
		protected:
			std::vector<uint8_t> getDigest() override {
				return std::vector<uint8_t>(context.digest, context.digest + 32);
			}
		private:
			typedef struct {
				uint64_t state[8], count[2];
				uint8_t  data[128], digest[32];
			} CTX;

			CTX context = { 0 };

			// constants (H) defined by SHA-512/256 algorithm
			// as per: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_256.pdf
			const std::array<uint64_t, 8> H{
				0x22312194FC2BF72C,
				0x9F555FA3C84C64C2,
				0x2393B86B6F53B151,
				0x963877195940EABD,
				0x96283EE2A88EFFE3,
				0xBE5E1E2553863992,
				0x2B0199FC2C85B8AA,
				0x0EB72DDC81C52CA2
			};

			// more constants (K)... as per above
			const std::array<uint64_t, 80> K{
				0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
				0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
				0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
				0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
				0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
				0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
				0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
				0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
				0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
				0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
				0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
				0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
				0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
				0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
				0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
				0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
				0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
				0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
				0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
				0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
			};

			void ctx_init() override;
			void ctx_transform(const uint8_t* data);
			void ctx_update(const uint8_t* data, size_t len) override;
			void ctx_final() override;

			constexpr uint64_t F(const uint64_t A, const uint64_t B, const uint64_t C);
			constexpr uint64_t G(const uint64_t A, const uint64_t B, const uint64_t C);

			// Sigma functions
			// as per: https://datatracker.ietf.org/doc/html/rfc4634
			uint64_t SIGMA0(const uint64_t A);
			uint64_t SIGMA1(const uint64_t A);
			uint64_t SIGMA2(const uint64_t A);
			uint64_t SIGMA3(const uint64_t A);
		};

		// SHA-1
		void hashpp::SHA::SHA1::ctx_init() {
			this->context = {
				{this->H[0], this->H[1], this->H[2], this->H[3], this->H[4]},
				{this->K[0], this->K[1], this->K[2], this->K[3]},
				0, 0
			};
		}
		void hashpp::SHA::SHA1::ctx_transform(const uint8_t* data) {
			uint32_t t, m[80], i = 0, j = 0;

			for (; i < 16; ++i, j += 4) {
				m[i] = this->A(data[j], data[j + 1], data[j + 2], data[j + 3]);
			}
			for (; i < 80; ++i) {
				m[i] = this->B(m[i - 3], m[i - 8], m[i - 14], m[i - 16]);
				m[i] = this->C(m[i]);
			}

			std::array<uint32_t, 5> results = {
				this->context.state[0],
				this->context.state[1],
				this->context.state[2],
				this->context.state[3],
				this->context.state[4]
			};

			for (i = 0; i < 20; ++i) {
				t = this->rl32(results[0], 5) + (F(results[1], results[2], results[3])) + results[4] + this->context.k[0] + m[i];
				results[4] = results[3];
				results[3] = results[2];
				results[2] = this->rl32(results[1], 30);
				results[1] = results[0];
				results[0] = t;
			}
			for (; i < 40; ++i) {
				t = this->rl32(results[0], 5) + (J(results[1], results[2], results[3])) + results[4] + this->context.k[1] + m[i];
				results[4] = results[3];
				results[3] = results[2];
				results[2] = this->rl32(results[1], 30);
				results[1] = results[0];
				results[0] = t;
			}
			for (; i < 60; ++i) {
				t = this->rl32(results[0], 5) + ((G(results[1], results[2], results[3]))) + results[4] + this->context.k[2] + m[i];
				results[4] = results[3];
				results[3] = results[2];
				results[2] = this->rl32(results[1], 30);
				results[1] = results[0];
				results[0] = t;
			}
			for (; i < 80; ++i) {
				t = this->rl32(results[0], 5) + (J(results[1], results[2], results[3])) + results[4] + this->context.k[3] + m[i];
				results[4] = results[3];
				results[3] = results[2];
				results[2] = this->rl32(results[1], 30);
				results[1] = results[0];
				results[0] = t;
			}

			for (uint32_t z = 0; z < 5; z++) {
				this->context.state[z] += results[z];
			}
		}
		void hashpp::SHA::SHA1::ctx_update(const uint8_t* data, size_t len) {
			size_t i;

			for (i = 0; i < len; ++i) {
				this->context.data[this->context.size] = data[i];
				this->context.size++;
				if (this->context.size == 64) {
					this->ctx_transform(this->context.data);
					this->context.bitsize += 512;
					this->context.size = 0;
				}
			}
		}
		void hashpp::SHA::SHA1::ctx_final() {
			uint32_t L = this->context.size;

			if (this->context.size < 56) {
				this->context.data[L++] = 0x80;
				while (L < 56) {
					this->context.data[L++] = 0x00;
				}
			}
			else {
				this->context.data[L++] = 0x80;
				while (L < 64) {
					this->context.data[L++] = 0x00;
				}
				this->ctx_transform(this->context.data);
				memset(this->context.data, 0, 56);
			}

			this->context.bitsize += static_cast<uint64_t>(this->context.size) * 8;
			this->context.data[63] = this->context.bitsize;
			this->context.data[62] = this->context.bitsize >> 8;
			this->context.data[61] = this->context.bitsize >> 16;
			this->context.data[60] = this->context.bitsize >> 24;
			this->context.data[59] = this->context.bitsize >> 32;
			this->context.data[58] = this->context.bitsize >> 40;
			this->context.data[57] = this->context.bitsize >> 48;
			this->context.data[56] = this->context.bitsize >> 56;
			this->ctx_transform(this->context.data);

			for (L = 0; L < 4; ++L) {
				this->context.digest[L] = (this->context.state[0] >> (24 - L * 8)) & 0x000000ff;
				this->context.digest[L + 4] = (this->context.state[1] >> (24 - L * 8)) & 0x000000ff;
				this->context.digest[L + 8] = (this->context.state[2] >> (24 - L * 8)) & 0x000000ff;
				this->context.digest[L + 12] = (this->context.state[3] >> (24 - L * 8)) & 0x000000ff;
				this->context.digest[L + 16] = (this->context.state[4] >> (24 - L * 8)) & 0x000000ff;
			}
		}
		constexpr uint32_t hashpp::SHA::SHA1::A(const uint32_t A, const uint32_t B, const uint32_t C, const uint32_t D) {
			return ((A << 24) + (B << 16) + (C << 8) + (D));
		}
		constexpr uint32_t hashpp::SHA::SHA1::B(const uint32_t A, const uint32_t B, const uint32_t C, const uint32_t D) {
			return ((A ^ B ^ C ^ D));
		}
		constexpr uint32_t hashpp::SHA::SHA1::C(const uint32_t A) { return ((A << 1) | (A >> 31)); }
		constexpr uint32_t hashpp::SHA::SHA1::F(const uint32_t B, const uint32_t C, const uint32_t D) { return ((B & C) ^ (~B & D)); }
		constexpr uint32_t hashpp::SHA::SHA1::G(const uint32_t B, const uint32_t C, const uint32_t D) { return ((B & C) ^ (B & D) ^ (C & D)); }
		constexpr uint32_t hashpp::SHA::SHA1::J(const uint32_t B, const uint32_t C, const uint32_t D) { return ((B ^ C ^ D)); }

		// SHA2-224
		void hashpp::SHA::SHA2_224::ctx_init() {
			this->context = {
				{this->H[0], this->H[1], this->H[2], this->H[3],
					this->H[4], this->H[5], this->H[6], this->H[7]},
				0, 0
			};
		}
		void hashpp::SHA::SHA2_224::ctx_transform(const uint8_t* data) {
			uint32_t m[64], i = 0, j = 0;

			for (; i < 16; ++i, j += 4) {
				m[i] = this->A(data[j], data[j + 1], data[j + 2], data[j + 3]);
			}			for (; i < 64; ++i) {
				m[i] = this->SIGMA3(m[i - 2]) + m[i - 7] + this->SIGMA2(m[i - 15]) + m[i - 16];
			}

			std::array<uint32_t, 8> results = {
				this->context.state[0],
				this->context.state[1],
				this->context.state[2],
				this->context.state[3],
				this->context.state[4],
				this->context.state[5],
				this->context.state[6],
				this->context.state[7]
			};

			uint32_t t1, t2;
			for (i = 0; i < 64; ++i) {
				t1 = results[7] + this->SIGMA1(results[4]) + this->F(results[4], results[5], results[6]) + this->K[i] + m[i];
				t2 = this->SIGMA0(results[0]) + this->G(results[0], results[1], results[2]);
				results[7] = results[6];
				results[6] = results[5];
				results[5] = results[4];
				results[4] = results[3] + t1;
				results[3] = results[2];
				results[2] = results[1];
				results[1] = results[0];
				results[0] = t1 + t2;
			}

			for (uint32_t z = 0; z < 8; z++) {
				this->context.state[z] += results[z];
			}
		}
		void hashpp::SHA::SHA2_224::ctx_update(const uint8_t* data, size_t len) {
			uint32_t i;

			for (i = 0; i < len; ++i) {
				this->context.data[this->context.size] = data[i];
				this->context.size++;
				if (this->context.size == 64) {
					this->ctx_transform(this->context.data);
					this->context.bitsize += 512;
					this->context.size = 0;
				}
			}
		}
		void hashpp::SHA::SHA2_224::ctx_final() {
			uint32_t i = this->context.size;

			if (this->context.size < 56) {
				this->context.data[i++] = 0x80;
				while (i < 56) {
					this->context.data[i++] = 0x00;
				}
			}
			else {
				this->context.data[i++] = 0x80;
				while (i < 64) {
					this->context.data[i++] = 0x00;
				}
				this->ctx_transform(this->context.data);
				memset(this->context.data, 0, 56);
			}

			this->context.bitsize += static_cast<uint64_t>(this->context.size) * 8;
			this->context.data[63] = this->context.bitsize;
			this->context.data[62] = this->context.bitsize >> 8;
			this->context.data[61] = this->context.bitsize >> 16;
			this->context.data[60] = this->context.bitsize >> 24;
			this->context.data[59] = this->context.bitsize >> 32;
			this->context.data[58] = this->context.bitsize >> 40;
			this->context.data[57] = this->context.bitsize >> 48;
			this->context.data[56] = this->context.bitsize >> 56;
			this->ctx_transform(this->context.data);

			for (i = 0; i < 4; ++i) {
				this->context.digest[i] = (this->context.state[0] >> (24 - i * 8)) & 0x000000ff;
				this->context.digest[i + 4] = (this->context.state[1] >> (24 - i * 8)) & 0x000000ff;
				this->context.digest[i + 8] = (this->context.state[2] >> (24 - i * 8)) & 0x000000ff;
				this->context.digest[i + 12] = (this->context.state[3] >> (24 - i * 8)) & 0x000000ff;
				this->context.digest[i + 16] = (this->context.state[4] >> (24 - i * 8)) & 0x000000ff;
				this->context.digest[i + 20] = (this->context.state[5] >> (24 - i * 8)) & 0x000000ff;
				this->context.digest[i + 24] = (this->context.state[6] >> (24 - i * 8)) & 0x000000ff;
			}
		}
		constexpr uint32_t hashpp::SHA::SHA2_224::A(const uint32_t A, const uint32_t B, const uint32_t C, const uint32_t D) {
			return ((A << 24) + (B << 16) + (C << 8) + (D));
		}
		constexpr uint32_t hashpp::SHA::SHA2_224::F(const uint32_t B, const uint32_t C, const uint32_t D) { return ((B & C) ^ (~B & D)); }
		constexpr uint32_t hashpp::SHA::SHA2_224::G(const uint32_t B, const uint32_t C, const uint32_t D) { return ((B & C) ^ (B & D) ^ (C & D)); }
		uint32_t hashpp::SHA::SHA2_224::SIGMA0(const uint32_t A) { return (this->rr32(A, 2) ^ this->rr32(A, 13) ^ this->rr32(A, 22)); }
		uint32_t hashpp::SHA::SHA2_224::SIGMA1(const uint32_t A) { return (this->rr32(A, 6) ^ this->rr32(A, 11) ^ this->rr32(A, 25)); }
		uint32_t hashpp::SHA::SHA2_224::SIGMA2(const uint32_t A) { return (this->rr32(A, 7) ^ this->rr32(A, 18) ^ ((A) >> 3)); }
		uint32_t hashpp::SHA::SHA2_224::SIGMA3(const uint32_t A) { return (this->rr32(A, 17) ^ this->rr32(A, 19) ^ ((A) >> 10)); }

		// SHA2-256
		void hashpp::SHA::SHA2_256::ctx_init() {
			this->context = {
				{this->H[0], this->H[1], this->H[2], this->H[3],
					this->H[4], this->H[5], this->H[6], this->H[7]},
				0, 0
			};
		}
		void hashpp::SHA::SHA2_256::ctx_transform(const uint8_t* data) {
			uint32_t m[64], i = 0, j = 0;

			for (; i < 16; ++i, j += 4) {
				m[i] = this->A(data[j], data[j + 1], data[j + 2], data[j + 3]);
			}
			for (; i < 64; ++i) {
				m[i] = this->SIGMA3(m[i - 2]) + m[i - 7] + this->SIGMA2(m[i - 15]) + m[i - 16];
			}

			std::array<uint32_t, 8> results = {
				this->context.state[0],
				this->context.state[1],
				this->context.state[2],
				this->context.state[3],
				this->context.state[4],
				this->context.state[5],
				this->context.state[6],
				this->context.state[7]
			};

			uint32_t t1, t2;
			for (i = 0; i < 64; ++i) {
				t1 = results[7] + this->SIGMA1(results[4]) + this->F(results[4], results[5], results[6]) + this->K[i] + m[i];
				t2 = this->SIGMA0(results[0]) + this->G(results[0], results[1], results[2]);
				results[7] = results[6];
				results[6] = results[5];
				results[5] = results[4];
				results[4] = results[3] + t1;
				results[3] = results[2];
				results[2] = results[1];
				results[1] = results[0];
				results[0] = t1 + t2;
			}

			for (uint32_t z = 0; z < 8; z++) {
				this->context.state[z] += results[z];
			}
		}
		void hashpp::SHA::SHA2_256::ctx_update(const uint8_t* data, size_t len) {
			uint32_t i;

			for (i = 0; i < len; ++i) {
				this->context.data[this->context.size] = data[i];
				this->context.size++;
				if (this->context.size == 64) {
					this->ctx_transform(this->context.data);
					this->context.bitsize += 512;
					this->context.size = 0;
				}
			}
		}
		void hashpp::SHA::SHA2_256::ctx_final() {
			uint32_t i = this->context.size;

			if (this->context.size < 56) {
				this->context.data[i++] = 0x80;
				while (i < 56) {
					this->context.data[i++] = 0x00;
				}
			}
			else {
				this->context.data[i++] = 0x80;
				while (i < 64) {
					this->context.data[i++] = 0x00;
				}
				this->ctx_transform(this->context.data);
				memset(this->context.data, 0, 56);
			}

			this->context.bitsize += static_cast<uint64_t>(this->context.size) * 8;
			this->context.data[63] = this->context.bitsize;
			this->context.data[62] = this->context.bitsize >> 8;
			this->context.data[61] = this->context.bitsize >> 16;
			this->context.data[60] = this->context.bitsize >> 24;
			this->context.data[59] = this->context.bitsize >> 32;
			this->context.data[58] = this->context.bitsize >> 40;
			this->context.data[57] = this->context.bitsize >> 48;
			this->context.data[56] = this->context.bitsize >> 56;
			this->ctx_transform(this->context.data);

			for (i = 0; i < 4; ++i) {
				this->context.digest[i] = (this->context.state[0] >> (24 - i * 8)) & 0x000000ff;
				this->context.digest[i + 4] = (this->context.state[1] >> (24 - i * 8)) & 0x000000ff;
				this->context.digest[i + 8] = (this->context.state[2] >> (24 - i * 8)) & 0x000000ff;
				this->context.digest[i + 12] = (this->context.state[3] >> (24 - i * 8)) & 0x000000ff;
				this->context.digest[i + 16] = (this->context.state[4] >> (24 - i * 8)) & 0x000000ff;
				this->context.digest[i + 20] = (this->context.state[5] >> (24 - i * 8)) & 0x000000ff;
				this->context.digest[i + 24] = (this->context.state[6] >> (24 - i * 8)) & 0x000000ff;
				this->context.digest[i + 28] = (this->context.state[7] >> (24 - i * 8)) & 0x000000ff;
			}
		}
		constexpr uint32_t hashpp::SHA::SHA2_256::A(const uint32_t A, const uint32_t B, const uint32_t C, const uint32_t D) {
			return ((A << 24) + (B << 16) + (C << 8) + (D));
		}
		constexpr uint32_t hashpp::SHA::SHA2_256::F(const uint32_t B, const uint32_t C, const uint32_t D) { return ((B & C) ^ (~B & D)); }
		constexpr uint32_t hashpp::SHA::SHA2_256::G(const uint32_t B, const uint32_t C, const uint32_t D) { return ((B & C) ^ (B & D) ^ (C & D)); }
		uint32_t hashpp::SHA::SHA2_256::SIGMA0(const uint32_t A) { return (this->rr32(A, 2) ^ this->rr32(A, 13) ^ this->rr32(A, 22)); }
		uint32_t hashpp::SHA::SHA2_256::SIGMA1(const uint32_t A) { return (this->rr32(A, 6) ^ this->rr32(A, 11) ^ this->rr32(A, 25)); }
		uint32_t hashpp::SHA::SHA2_256::SIGMA2(const uint32_t A) { return (this->rr32(A, 7) ^ this->rr32(A, 18) ^ ((A) >> 3)); }
		uint32_t hashpp::SHA::SHA2_256::SIGMA3(const uint32_t A) { return (this->rr32(A, 17) ^ this->rr32(A, 19) ^ ((A) >> 10)); }

		// SHA2-384
		void hashpp::SHA::SHA2_384::ctx_init() {
			this->context = {
				{this->H[0], this->H[1], this->H[2], this->H[3],
					this->H[4], this->H[5], this->H[6], this->H[7]},
				{0, 0}
			};
		}
		void hashpp::SHA::SHA2_384::ctx_transform(const uint8_t* data) {
			uint64_t W[80];
			uint32_t i;

			std::array<uint64_t, 8> results = {
				this->context.state[0],
				this->context.state[1],
				this->context.state[2],
				this->context.state[3],
				this->context.state[4],
				this->context.state[5],
				this->context.state[6],
				this->context.state[7]
			};

			for (i = 0; i < 16; i++) {
				GU64B(W[i], data, 8 * i);
				uint64_t t1, t2;
				t1 = (results[7]) + this->SIGMA1((results[4])) + this->F((results[4]), (results[5]), (results[6])) + (this->K[i]) + (W[i]);
				t2 = this->SIGMA0((results[0])) + this->G((results[0]), (results[1]), (results[2]));
				(results[7]) = (results[6]);
				(results[6]) = (results[5]);
				(results[5]) = (results[4]);
				(results[4]) = (results[3]) + t1;
				(results[3]) = (results[2]);
				(results[2]) = (results[1]);
				(results[1]) = (results[0]);
				(results[0]) = t1 + t2;
			}

			for (i = 16; i < 80; i++) {
				W[i] = this->SIGMA3(W[i - 2]) + W[i - 7] + this->SIGMA2(W[i - 15]) + W[i - 16];
				uint64_t t1, t2;
				t1 = (results[7]) + this->SIGMA1((results[4])) + this->F((results[4]), (results[5]), (results[6])) + (this->K[i]) + (W[i]);
				t2 = this->SIGMA0((results[0])) + this->G((results[0]), (results[1]), (results[2]));
				(results[7]) = (results[6]);
				(results[6]) = (results[5]);
				(results[5]) = (results[4]);
				(results[4]) = (results[3]) + t1;
				(results[3]) = (results[2]);
				(results[2]) = (results[1]);
				(results[1]) = (results[0]);
				(results[0]) = t1 + t2;
			}

			for (uint32_t z = 0; z < 8; z++) {
				this->context.state[z] += results[z];
			}
		}
		void hashpp::SHA::SHA2_384::ctx_update(const uint8_t* data, size_t len) {
			uint32_t left, fill, rlen = len;
			const uint8_t* ptr = data;

			if (len != 0) {

				left = this->context.count[0] & 0x7F; fill = 128 - left;

				this->context.count[0] += len;
				if ((this->context.count[0]) < (len)) {
					(this->context.count[1])++;
				}

				if ((left > 0) && (rlen >= fill)) {
					memcpy(this->context.data + left, ptr, fill);
					this->ctx_transform(this->context.data);
					ptr += fill;
					rlen -= fill;
					left = 0;
				}

				while (rlen >= 128) {
					this->ctx_transform(ptr);
					ptr += 128;
					rlen -= 128;
				}

				if (rlen > 0) {
					memcpy(this->context.data + left, ptr, rlen);
				}
			}
		}
		void hashpp::SHA::SHA2_384::ctx_final() {
			uint32_t block_present = 0;
			uint8_t last_padded_block[2 * 128];

			memset(last_padded_block, 0, sizeof(last_padded_block));

			block_present = this->context.count[0] % 128;
			if (block_present != 0) {
				memcpy(last_padded_block, this->context.data, block_present);
			}

			last_padded_block[block_present] = 0x80;

			if (block_present > (128 - 1 - (2 * sizeof(uint64_t)))) {
				PU128B(this->context.count[0], this->context.count[1], last_padded_block, 2 * (128 - sizeof(uint64_t)));
				this->ctx_transform(last_padded_block);
				this->ctx_transform(last_padded_block + 128);
			}
			else {
				PU128B(this->context.count[0], this->context.count[1],
					last_padded_block,
					128 - (2 * sizeof(uint64_t)));
				this->ctx_transform(last_padded_block);
			}

			PU64B(this->context.state[0], this->context.digest, 0);
			PU64B(this->context.state[1], this->context.digest, 8);
			PU64B(this->context.state[2], this->context.digest, 16);
			PU64B(this->context.state[3], this->context.digest, 24);
			PU64B(this->context.state[4], this->context.digest, 32);
			PU64B(this->context.state[5], this->context.digest, 40);
		}
		constexpr uint64_t hashpp::SHA::SHA2_384::F(const uint64_t A, const uint64_t B, const uint64_t C) { return ((A & B) ^ (~A & C)); }
		constexpr uint64_t hashpp::SHA::SHA2_384::G(const uint64_t A, const uint64_t B, const uint64_t C) { return ((A & B) ^ (A & C) ^ (B & C)); }
		uint64_t hashpp::SHA::SHA2_384::SIGMA0(const uint64_t A) { return this->rr64(A, 28) ^ this->rr64(A, 34) ^ this->rr64(A, 39); }
		uint64_t hashpp::SHA::SHA2_384::SIGMA1(const uint64_t A) { return this->rr64(A, 14) ^ this->rr64(A, 18) ^ this->rr64(A, 41); }
		uint64_t hashpp::SHA::SHA2_384::SIGMA2(const uint64_t A) { return this->rr64(A, 1) ^ this->rr64(A, 8) ^ (A >> 7); }
		uint64_t hashpp::SHA::SHA2_384::SIGMA3(const uint64_t A) { return this->rr64(A, 19) ^ this->rr64(A, 61) ^ (A >> 6); }

		// SHA2-512
		void hashpp::SHA::SHA2_512::ctx_init() {
			this->context = {
				{this->H[0], this->H[1], this->H[2], this->H[3],
					this->H[4], this->H[5], this->H[6], this->H[7]},
				{0, 0}
			};
		}
		void hashpp::SHA::SHA2_512::ctx_transform(const uint8_t* data) {
			uint64_t W[80];
			uint32_t i;

			std::array<uint64_t, 8> results = {
				this->context.state[0],
				this->context.state[1],
				this->context.state[2],
				this->context.state[3],
				this->context.state[4],
				this->context.state[5],
				this->context.state[6],
				this->context.state[7]
			};

			for (i = 0; i < 16; i++) {
				GU64B(W[i], data, 8 * i);
				uint64_t t1, t2;
				t1 = (results[7]) + this->SIGMA1((results[4])) + this->F((results[4]), (results[5]), (results[6])) + (this->K[i]) + (W[i]);
				t2 = this->SIGMA0((results[0])) + this->G((results[0]), (results[1]), (results[2]));
				(results[7]) = (results[6]);
				(results[6]) = (results[5]);
				(results[5]) = (results[4]);
				(results[4]) = (results[3]) + t1;
				(results[3]) = (results[2]);
				(results[2]) = (results[1]);
				(results[1]) = (results[0]);
				(results[0]) = t1 + t2;
			}

			for (i = 16; i < 80; i++) {
				W[i] = this->SIGMA3(W[i - 2]) + W[i - 7] + this->SIGMA2(W[i - 15]) + W[i - 16];
				uint64_t t1, t2;
				t1 = (results[7]) + this->SIGMA1((results[4])) + this->F((results[4]), (results[5]), (results[6])) + (this->K[i]) + (W[i]);
				t2 = this->SIGMA0((results[0])) + this->G((results[0]), (results[1]), (results[2]));
				(results[7]) = (results[6]);
				(results[6]) = (results[5]);
				(results[5]) = (results[4]);
				(results[4]) = (results[3]) + t1;
				(results[3]) = (results[2]);
				(results[2]) = (results[1]);
				(results[1]) = (results[0]);
				(results[0]) = t1 + t2;
			}

			for (uint32_t z = 0; z < 8; z++) {
				this->context.state[z] += results[z];
			}
		}
		void hashpp::SHA::SHA2_512::ctx_update(const uint8_t* data, size_t len) {
			uint32_t left, fill, rlen = len;
			const uint8_t* ptr = data;

			if (len != 0) {

				left = this->context.count[0] & 0x7F; fill = 128 - left;

				this->context.count[0] += len;
				if ((this->context.count[0]) < (len)) {
					(this->context.count[1])++;
				}

				if ((left > 0) && (rlen >= fill)) {
					memcpy(this->context.data + left, ptr, fill);
					this->ctx_transform(this->context.data);
					ptr += fill;
					rlen -= fill;
					left = 0;
				}

				while (rlen >= 128) {
					this->ctx_transform(ptr);
					ptr += 128;
					rlen -= 128;
				}

				if (rlen > 0) {
					memcpy(this->context.data + left, ptr, rlen);
				}
			}
		}
		void hashpp::SHA::SHA2_512::ctx_final() {
			uint32_t block_present = 0;
			uint8_t last_padded_block[2 * 128];

			memset(last_padded_block, 0, sizeof(last_padded_block));

			block_present = this->context.count[0] % 128;
			if (block_present != 0) {
				memcpy(last_padded_block, this->context.data, block_present);
			}

			last_padded_block[block_present] = 0x80;

			if (block_present > (128 - 1 - (2 * sizeof(uint64_t)))) {
				PU128B(this->context.count[0], this->context.count[1], last_padded_block, 2 * (128 - sizeof(uint64_t)));
				this->ctx_transform(last_padded_block);
				this->ctx_transform(last_padded_block + 128);
			}
			else {
				PU128B(this->context.count[0], this->context.count[1],
					last_padded_block,
					128 - (2 * sizeof(uint64_t)));
				this->ctx_transform(last_padded_block);
			}

			PU64B(this->context.state[0], this->context.digest, 0);
			PU64B(this->context.state[1], this->context.digest, 8);
			PU64B(this->context.state[2], this->context.digest, 16);
			PU64B(this->context.state[3], this->context.digest, 24);
			PU64B(this->context.state[4], this->context.digest, 32);
			PU64B(this->context.state[5], this->context.digest, 40);
			PU64B(this->context.state[6], this->context.digest, 48);
			PU64B(this->context.state[7], this->context.digest, 56);
		}
		constexpr uint64_t hashpp::SHA::SHA2_512::F(const uint64_t A, const uint64_t B, const uint64_t C) { return ((A & B) ^ (~A & C)); }
		constexpr uint64_t hashpp::SHA::SHA2_512::G(const uint64_t A, const uint64_t B, const uint64_t C) { return ((A & B) ^ (A & C) ^ (B & C)); }
		uint64_t hashpp::SHA::SHA2_512::SIGMA0(const uint64_t A) { return this->rr64(A, 28) ^ this->rr64(A, 34) ^ this->rr64(A, 39); }
		uint64_t hashpp::SHA::SHA2_512::SIGMA1(const uint64_t A) { return this->rr64(A, 14) ^ this->rr64(A, 18) ^ this->rr64(A, 41); }
		uint64_t hashpp::SHA::SHA2_512::SIGMA2(const uint64_t A) { return this->rr64(A, 1) ^ this->rr64(A, 8) ^ (A >> 7); }
		uint64_t hashpp::SHA::SHA2_512::SIGMA3(const uint64_t A) { return this->rr64(A, 19) ^ this->rr64(A, 61) ^ (A >> 6); }

		// SHA2-512-224
		void hashpp::SHA::SHA2_512_224::ctx_init() {
			this->context = {
				{this->H[0], this->H[1], this->H[2], this->H[3],
					this->H[4], this->H[5], this->H[6], this->H[7]},
				{0, 0}
			};
		}
		void hashpp::SHA::SHA2_512_224::ctx_transform(const uint8_t* data) {
			uint64_t W[80];
			uint32_t i;

			std::array<uint64_t, 8> results = {
				this->context.state[0],
				this->context.state[1],
				this->context.state[2],
				this->context.state[3],
				this->context.state[4],
				this->context.state[5],
				this->context.state[6],
				this->context.state[7]
			};

			for (i = 0; i < 16; i++) {
				GU64B(W[i], data, 8 * i);
				uint64_t t1, t2;
				t1 = (results[7]) + this->SIGMA1((results[4])) + this->F((results[4]), (results[5]), (results[6])) + (this->K[i]) + (W[i]);
				t2 = this->SIGMA0((results[0])) + this->G((results[0]), (results[1]), (results[2]));
				(results[7]) = (results[6]);
				(results[6]) = (results[5]);
				(results[5]) = (results[4]);
				(results[4]) = (results[3]) + t1;
				(results[3]) = (results[2]);
				(results[2]) = (results[1]);
				(results[1]) = (results[0]);
				(results[0]) = t1 + t2;
			}

			for (i = 16; i < 80; i++) {
				W[i] = this->SIGMA3(W[i - 2]) + W[i - 7] + this->SIGMA2(W[i - 15]) + W[i - 16];
				uint64_t t1, t2;
				t1 = (results[7]) + this->SIGMA1((results[4])) + this->F((results[4]), (results[5]), (results[6])) + (this->K[i]) + (W[i]);
				t2 = this->SIGMA0((results[0])) + this->G((results[0]), (results[1]), (results[2]));
				(results[7]) = (results[6]);
				(results[6]) = (results[5]);
				(results[5]) = (results[4]);
				(results[4]) = (results[3]) + t1;
				(results[3]) = (results[2]);
				(results[2]) = (results[1]);
				(results[1]) = (results[0]);
				(results[0]) = t1 + t2;
			}

			for (uint32_t z = 0; z < 8; z++) {
				this->context.state[z] += results[z];
			}
		}
		void hashpp::SHA::SHA2_512_224::ctx_update(const uint8_t* data, size_t len) {
			uint32_t left, fill, rlen = len;
			const uint8_t* ptr = data;

			if (len != 0) {

				left = this->context.count[0] & 0x7F; fill = 128 - left;

				this->context.count[0] += len;
				if ((this->context.count[0]) < (len)) {
					(this->context.count[1])++;
				}

				if ((left > 0) && (rlen >= fill)) {
					memcpy(this->context.data + left, ptr, fill);
					this->ctx_transform(this->context.data);
					ptr += fill;
					rlen -= fill;
					left = 0;
				}

				while (rlen >= 128) {
					this->ctx_transform(ptr);
					ptr += 128;
					rlen -= 128;
				}

				if (rlen > 0) {
					memcpy(this->context.data + left, ptr, rlen);
				}
			}
		}
		void hashpp::SHA::SHA2_512_224::ctx_final() {
			uint32_t block_present = 0;
			uint8_t last_padded_block[2 * 128];

			memset(last_padded_block, 0, sizeof(last_padded_block));

			block_present = this->context.count[0] % 128;
			if (block_present != 0) {
				memcpy(last_padded_block, this->context.data, block_present);
			}

			last_padded_block[block_present] = 0x80;

			if (block_present > (128 - 1 - (2 * sizeof(uint64_t)))) {
				/* We need an additional block */
				PU128B(this->context.count[0], this->context.count[1], last_padded_block, 2 * (128 - sizeof(uint64_t)));
				this->ctx_transform(last_padded_block);
				this->ctx_transform(last_padded_block + 128);
			}
			else {
				PU128B(this->context.count[0], this->context.count[1],
					last_padded_block,
					128 - (2 * sizeof(uint64_t)));
				this->ctx_transform(last_padded_block);
			}

			PU64B(this->context.state[0], this->context.digest, 0);
			PU64B(this->context.state[1], this->context.digest, 8);
			PU64B(this->context.state[2], this->context.digest, 16);
			PU64B(this->context.state[3], this->context.digest, 24);
		}
		constexpr uint64_t hashpp::SHA::SHA2_512_224::F(const uint64_t A, const uint64_t B, const uint64_t C) { return ((A & B) ^ (~A & C)); }
		constexpr uint64_t hashpp::SHA::SHA2_512_224::G(const uint64_t A, const uint64_t B, const uint64_t C) { return ((A & B) ^ (A & C) ^ (B & C)); }
		uint64_t hashpp::SHA::SHA2_512_224::SIGMA0(const uint64_t A) { return this->rr64(A, 28) ^ this->rr64(A, 34) ^ this->rr64(A, 39); }
		uint64_t hashpp::SHA::SHA2_512_224::SIGMA1(const uint64_t A) { return this->rr64(A, 14) ^ this->rr64(A, 18) ^ this->rr64(A, 41); }
		uint64_t hashpp::SHA::SHA2_512_224::SIGMA2(const uint64_t A) { return this->rr64(A, 1) ^ this->rr64(A, 8) ^ (A >> 7); }
		uint64_t hashpp::SHA::SHA2_512_224::SIGMA3(const uint64_t A) { return this->rr64(A, 19) ^ this->rr64(A, 61) ^ (A >> 6); }

		// SHA2-512-256
		void hashpp::SHA::SHA2_512_256::ctx_init() {
			this->context = {
				{this->H[0], this->H[1], this->H[2], this->H[3],
					this->H[4], this->H[5], this->H[6], this->H[7]},
				{0, 0}
			};
		}
		void hashpp::SHA::SHA2_512_256::ctx_transform(const uint8_t* data) {
			uint64_t W[80];
			uint32_t i;

			std::array<uint64_t, 8> results = {
				this->context.state[0],
				this->context.state[1],
				this->context.state[2],
				this->context.state[3],
				this->context.state[4],
				this->context.state[5],
				this->context.state[6],
				this->context.state[7]
			};

			for (i = 0; i < 16; i++) {
				GU64B(W[i], data, 8 * i);
				uint64_t t1, t2;
				t1 = (results[7]) + this->SIGMA1((results[4])) + this->F((results[4]), (results[5]), (results[6])) + (this->K[i]) + (W[i]);
				t2 = this->SIGMA0((results[0])) + this->G((results[0]), (results[1]), (results[2]));
				(results[7]) = (results[6]);
				(results[6]) = (results[5]);
				(results[5]) = (results[4]);
				(results[4]) = (results[3]) + t1;
				(results[3]) = (results[2]);
				(results[2]) = (results[1]);
				(results[1]) = (results[0]);
				(results[0]) = t1 + t2;
			}

			for (i = 16; i < 80; i++) {
				W[i] = this->SIGMA3(W[i - 2]) + W[i - 7] + this->SIGMA2(W[i - 15]) + W[i - 16];
				uint64_t t1, t2;
				t1 = (results[7]) + this->SIGMA1((results[4])) + this->F((results[4]), (results[5]), (results[6])) + (this->K[i]) + (W[i]);
				t2 = this->SIGMA0((results[0])) + this->G((results[0]), (results[1]), (results[2]));
				(results[7]) = (results[6]);
				(results[6]) = (results[5]);
				(results[5]) = (results[4]);
				(results[4]) = (results[3]) + t1;
				(results[3]) = (results[2]);
				(results[2]) = (results[1]);
				(results[1]) = (results[0]);
				(results[0]) = t1 + t2;
			}

			for (uint32_t z = 0; z < 8; z++) {
				this->context.state[z] += results[z];
			}
		}
		void hashpp::SHA::SHA2_512_256::ctx_update(const uint8_t* data, size_t len) {
			uint32_t left, fill, rlen = len;
			const uint8_t* ptr = data;

			if (len != 0) {

				left = this->context.count[0] & 0x7F; fill = 128 - left;

				this->context.count[0] += len;
				if ((this->context.count[0]) < (len)) {
					(this->context.count[1])++;
				}

				if ((left > 0) && (rlen >= fill)) {
					memcpy(this->context.data + left, ptr, fill);
					this->ctx_transform(this->context.data);
					ptr += fill;
					rlen -= fill;
					left = 0;
				}

				while (rlen >= 128) {
					this->ctx_transform(ptr);
					ptr += 128;
					rlen -= 128;
				}

				if (rlen > 0) {
					memcpy(this->context.data + left, ptr, rlen);
				}
			}
		}
		void hashpp::SHA::SHA2_512_256::ctx_final() {
			uint32_t block_present = 0;
			uint8_t last_padded_block[2 * 128];

			memset(last_padded_block, 0, sizeof(last_padded_block));

			block_present = this->context.count[0] % 128;
			if (block_present != 0) {
				memcpy(last_padded_block, this->context.data, block_present);
			}

			last_padded_block[block_present] = 0x80;

			if (block_present > (128 - 1 - (2 * sizeof(uint64_t)))) {
				PU128B(this->context.count[0], this->context.count[1], last_padded_block, 2 * (128 - sizeof(uint64_t)));
				this->ctx_transform(last_padded_block);
				this->ctx_transform(last_padded_block + 128);
			}
			else {
				PU128B(this->context.count[0], this->context.count[1],
					last_padded_block,
					128 - (2 * sizeof(uint64_t)));
				this->ctx_transform(last_padded_block);
			}

			PU64B(this->context.state[0], this->context.digest, 0);
			PU64B(this->context.state[1], this->context.digest, 8);
			PU64B(this->context.state[2], this->context.digest, 16);
			PU64B(this->context.state[3], this->context.digest, 24);
		}
		constexpr uint64_t hashpp::SHA::SHA2_512_256::F(const uint64_t A, const uint64_t B, const uint64_t C) { return ((A & B) ^ (~A & C)); }
		constexpr uint64_t hashpp::SHA::SHA2_512_256::G(const uint64_t A, const uint64_t B, const uint64_t C) { return ((A & B) ^ (A & C) ^ (B & C)); }
		uint64_t hashpp::SHA::SHA2_512_256::SIGMA0(const uint64_t A) { return this->rr64(A, 28) ^ this->rr64(A, 34) ^ this->rr64(A, 39); }
		uint64_t hashpp::SHA::SHA2_512_256::SIGMA1(const uint64_t A) { return this->rr64(A, 14) ^ this->rr64(A, 18) ^ this->rr64(A, 41); }
		uint64_t hashpp::SHA::SHA2_512_256::SIGMA2(const uint64_t A) { return this->rr64(A, 1) ^ this->rr64(A, 8) ^ (A >> 7); }
		uint64_t hashpp::SHA::SHA2_512_256::SIGMA3(const uint64_t A) { return this->rr64(A, 19) ^ this->rr64(A, 61) ^ (A >> 6); }
	}


	// class used to store hash retrieved from get*Hash
	// this class is used as an interface to access a
	// hash returned by the above described function(s)

	class hash {
	public:
		hash() = default;
		hash(std::string hex) : hashStr(hex) {}

		bool valid() noexcept { return !this->hashStr.empty(); }
		std::string getString() noexcept { return this->hashStr; };

		template <typename _Ty>
		friend std::ostream& operator<<(std::ostream& _Ostr, _Ty object) {
			_Ostr << object.hashStr;
			return _Ostr;
		}
	private:
		std::string hashStr;
	};


	// class used to store hashes retrieved from get*Hashes
	// this class is used to access multiple returned hashes
	// of one or more hash algorithms
	//
	// for instance, we can get several hashes of several algorithms and print only 
	// selected algorithms like so:
	//   auto allHashes = hashpp::get::getHashes({ {hashpp::ALGORITHMS::MD4, {"data1", "data2"}},
	//                                             {hashpp::ALGORITHMS::MD5, {"data1", "data2"}} });
	//   for (auto hash : allHashes["MD5"]) {
	//       std::cout << hash << std::endl;
	//   }
	//   for (auto hash : allHashes["MD4"]) {
	//       std::cout << hash << std::endl;
	//   }
	//
	//   ... et cetera, et cetera ...

	class hashCollection {
	public:
		hashCollection(std::vector<std::pair<std::string, std::vector<std::string>>> data) : collection(data) {}

		// operator[] overload to access collections of hashpp
		// by their specific algorithm
		std::vector<std::string> operator[](std::string algoID) {
			return this->getHashesFromID(algoID);
		}

		// function used to check if there are any hashes in the collection
		// under the requested algorithm
		//
		// for instance, the below will check if allHashes has hashpp of type MD5
		// auto allHashes = getHashes(...); if (allHashes.valid("MD5")) { ... }
		bool valid(std::string algoID) noexcept { return !this->operator[](algoID).empty(); }

		std::vector<std::pair<std::string, std::vector<std::string>>>::const_iterator begin() const noexcept {
			return this->collection.begin();
		}
		std::vector<std::pair<std::string, std::vector<std::string>>>::const_iterator end() const noexcept {
			return this->collection.end();
		}

	private:
		std::vector<std::pair<std::string, std::vector<std::string>>> collection;
		std::vector<std::string> getHashesFromID(std::string algoID) {
			for (std::pair<std::string, std::vector<std::string>> idHashCollectionPair : this->collection) {
				if (!idHashCollectionPair.first.compare(algoID)) {
					return idHashCollectionPair.second;
				}
			}
			// if no pair in collection contains requested algorithm ID
			// just return an empty vector
			return std::vector<std::string>();
		}
	};


	//  interface class to allow use of static methods to access
	//  all algorithm classes and use their functions without
	//  the need of several instantiations of each class in 
	//  the main source code of the user
	//
	//  i.e., if a user wants to pass data to one or several
	//  algorithms and get the hash(es), they can do so via:
	//  hashpp::get::getHash or hashpp::get::getHashes
	//
	//  the retrieval of file hashes is also possible via
	//  hashpp::get::getFileHash or collectively via 
	//  hashpp::get::getFileHashes
	//
	//  all hashpp::get methods return a hashpp::hash or a 
	//  hashpp::hashCollection object.
	//
	//  refer to the class definitions of both hashpp::hash and 
	//  hashpp::hashCollection for info on how to use them

	class get {
	public:
		// function to return a resulting hash from selected ALGORITHM and passed data
		static hashpp::hash getHash(hashpp::ALGORITHMS algorithm, std::string data) {
			switch (algorithm) {
				case hashpp::ALGORITHMS::MD5: {
					return { hashpp::MD::MD5().getHash(data) };
				}
				case hashpp::ALGORITHMS::MD4: {
					return { hashpp::MD::MD4().getHash(data) };
				}
				case hashpp::ALGORITHMS::MD2: {
					return { hashpp::MD::MD2().getHash(data) };
				}
				case hashpp::ALGORITHMS::SHA1: {
					return { hashpp::SHA::SHA1().getHash(data) };
				}
				case hashpp::ALGORITHMS::SHA2_224: {
					return { hashpp::SHA::SHA2_224().getHash(data) };
				}
				case hashpp::ALGORITHMS::SHA2_256: {
					return { hashpp::SHA::SHA2_256().getHash(data) };
				}
				case hashpp::ALGORITHMS::SHA2_384: {
					return { hashpp::SHA::SHA2_384().getHash(data) };
				}
				case hashpp::ALGORITHMS::SHA2_512: {
					return { hashpp::SHA::SHA2_512().getHash(data) };
				}
				case hashpp::ALGORITHMS::SHA2_512_224: {
					return { hashpp::SHA::SHA2_512_224().getHash(data) };
				}
				case hashpp::ALGORITHMS::SHA2_512_256: {
					return { hashpp::SHA::SHA2_512_256().getHash(data) };
				}
				default: {
					return hashpp::hash();
				}
			}
		}

		// function to return a collection of resulting hashes from selected ALGORITHMS and passed data
		static hashpp::hashCollection getHashes(std::vector<std::pair<hashpp::ALGORITHMS, std::vector<std::string>>> algorithmDataPairs) {
			std::vector<std::string> vMD5, vMD4, vMD2, vSHA1, vSHA2_224, vSHA2_256, vSHA2_384, vSHA2_512, vSHA2_512_224, vSHA2_512_256;

			for (std::pair<hashpp::ALGORITHMS, std::vector<std::string>> twin : algorithmDataPairs) {
				for (std::string _data : twin.second) {
					switch (twin.first) {
						case hashpp::ALGORITHMS::MD5: {
							vMD5.push_back(hashpp::MD::MD5().getHash(_data));
							break;
						}
						case hashpp::ALGORITHMS::MD4: {
							vMD4.push_back(hashpp::MD::MD4().getHash(_data));
							break;
						}
						case hashpp::ALGORITHMS::MD2: {
							vMD2.push_back(hashpp::MD::MD2().getHash(_data));
							break;
						}
						case hashpp::ALGORITHMS::SHA1: {
							vSHA1.push_back(hashpp::SHA::SHA1().getHash(_data));
							break;
						}
						case hashpp::ALGORITHMS::SHA2_224: {
							vSHA2_224.push_back(hashpp::SHA::SHA2_224().getHash(_data));
							break;
						}
						case hashpp::ALGORITHMS::SHA2_256: {
							vSHA2_256.push_back(hashpp::SHA::SHA2_256().getHash(_data));
							break;
						}
						case hashpp::ALGORITHMS::SHA2_384: {
							vSHA2_384.push_back(hashpp::SHA::SHA2_384().getHash(_data));
							break;
						}
						case hashpp::ALGORITHMS::SHA2_512: {
							vSHA2_512.push_back(hashpp::SHA::SHA2_512().getHash(_data));
							break;
						}
						case hashpp::ALGORITHMS::SHA2_512_224: {
							vSHA2_512_224.push_back(hashpp::SHA::SHA2_512_224().getHash(_data));
							break;
						}
						case hashpp::ALGORITHMS::SHA2_512_256: {
							vSHA2_512_256.push_back(hashpp::SHA::SHA2_512_256().getHash(_data));
							break;
						}
					}
				}
			}
			return hashCollection{
				{
					{ "MD5", vMD5 },
					{ "MD4", vMD4 },
					{ "MD2", vMD2 },
					{ "SHA1", vSHA1 },
					{ "SHA2-224", vSHA2_224 },
					{ "SHA2-256", vSHA2_256 },
					{ "SHA2-384", vSHA2_384 },
					{ "SHA2-512", vSHA2_512 },
					{ "SHA2-512-224", vSHA2_512_224 },
					{ "SHA2-512-256", vSHA2_512_256 }
				}
			};
		}

		// function to return a resulting hash from selected ALGORITHM and passed file
		static hashpp::hash getFileHash(hashpp::ALGORITHMS algorithm, std::string path) {
			if (std::filesystem::exists(path) && std::filesystem::is_regular_file(path)) {
				switch (algorithm) {
					case hashpp::ALGORITHMS::MD5: {
						return hashpp::MD::MD5().getHash(std::filesystem::path(path));
					}
					case hashpp::ALGORITHMS::MD4: {
						return hashpp::MD::MD4().getHash(std::filesystem::path(path));
					}
					case hashpp::ALGORITHMS::MD2: {
						return hashpp::MD::MD2().getHash(std::filesystem::path(path));
					}
					case hashpp::ALGORITHMS::SHA1: {
						return hashpp::SHA::SHA1().getHash(std::filesystem::path(path));
					}
					case hashpp::ALGORITHMS::SHA2_224: {
						return hashpp::SHA::SHA2_224().getHash(std::filesystem::path(path));
					}
					case hashpp::ALGORITHMS::SHA2_256: {
						return hashpp::SHA::SHA2_256().getHash(std::filesystem::path(path));
					}
					case hashpp::ALGORITHMS::SHA2_384: {
						return hashpp::SHA::SHA2_384().getHash(std::filesystem::path(path));
					}
					case hashpp::ALGORITHMS::SHA2_512: {
						return hashpp::SHA::SHA2_512().getHash(std::filesystem::path(path));
					}
					case hashpp::ALGORITHMS::SHA2_512_224: {
						return hashpp::SHA::SHA2_512_224().getHash(std::filesystem::path(path));
					}
					case hashpp::ALGORITHMS::SHA2_512_256: {
						return hashpp::SHA::SHA2_512_256().getHash(std::filesystem::path(path));
					}
					default: {
						return hashpp::hash();
					}
				}
			}
			else {
				return hashpp::hash();
			}
		}

		// function to return a collection of resulting hashes from selected ALGORITHMS and passed files (with recursive directory support)
		static hashpp::hashCollection getFilesHashes(std::vector<std::pair<hashpp::ALGORITHMS, std::vector<std::string>>> algorithmPathPairs) {
			std::vector<std::string> vMD5, vMD4, vMD2, vSHA1, vSHA2_224, vSHA2_256, vSHA2_384, vSHA2_512, vSHA2_512_224, vSHA2_512_256;

			for (std::pair<hashpp::ALGORITHMS, std::vector<std::string>> twin : algorithmPathPairs) {
				for (std::string _path : twin.second) {
					if (std::filesystem::exists(_path) && std::filesystem::is_regular_file(_path)) {
						switch (twin.first) {
							case hashpp::ALGORITHMS::MD5: {
								vMD5.push_back(hashpp::MD::MD5().getHash(std::filesystem::path(_path)));
								break;
							}
							case hashpp::ALGORITHMS::MD4: {
								vMD4.push_back(hashpp::MD::MD4().getHash(std::filesystem::path(_path)));
								break;
							}
							case hashpp::ALGORITHMS::MD2: {
								vMD2.push_back(hashpp::MD::MD2().getHash(std::filesystem::path(_path)));
								break;
							}
							case hashpp::ALGORITHMS::SHA1: {
								vSHA1.push_back(hashpp::SHA::SHA1().getHash(std::filesystem::path(_path)));
								break;
							}
							case hashpp::ALGORITHMS::SHA2_224: {
								vSHA2_224.push_back(hashpp::SHA::SHA2_224().getHash(std::filesystem::path(_path)));
								break;
							}
							case hashpp::ALGORITHMS::SHA2_256: {
								vSHA2_256.push_back(hashpp::SHA::SHA2_256().getHash(std::filesystem::path(_path)));
								break;
							}
							case hashpp::ALGORITHMS::SHA2_384: {
								vSHA2_384.push_back(hashpp::SHA::SHA2_384().getHash(std::filesystem::path(_path)));
								break;
							}
							case hashpp::ALGORITHMS::SHA2_512: {
								vSHA2_512.push_back(hashpp::SHA::SHA2_512().getHash(std::filesystem::path(_path)));
								break;
							}
							case hashpp::ALGORITHMS::SHA2_512_224: {
								vSHA2_512_224.push_back(hashpp::SHA::SHA2_512_224().getHash(std::filesystem::path(_path)));
								break;
							}
							case hashpp::ALGORITHMS::SHA2_512_256: {
								vSHA2_512_256.push_back(hashpp::SHA::SHA2_512_256().getHash(std::filesystem::path(_path)));
								break;
							}
						}
					}
					else if (std::filesystem::exists(_path) && std::filesystem::is_directory(_path)) {
						for (auto& item : std::filesystem::recursive_directory_iterator(_path)) {
							if (item.is_regular_file()) {
								switch (twin.first) {
									case hashpp::ALGORITHMS::MD5: {
										vMD5.push_back(hashpp::MD::MD5().getHash(item.path()));
										break;
									}
									case hashpp::ALGORITHMS::MD4: {
										vMD4.push_back(hashpp::MD::MD4().getHash(item.path()));
										break;
									}
									case hashpp::ALGORITHMS::MD2: {
										vMD2.push_back(hashpp::MD::MD2().getHash(item.path()));
										break;
									}
									case hashpp::ALGORITHMS::SHA1: {
										vSHA1.push_back(hashpp::SHA::SHA1().getHash(item.path()));
										break;
									}
									case hashpp::ALGORITHMS::SHA2_224: {
										vSHA2_224.push_back(hashpp::SHA::SHA2_224().getHash(item.path()));
										break;
									}
									case hashpp::ALGORITHMS::SHA2_256: {
										vSHA2_256.push_back(hashpp::SHA::SHA2_256().getHash(item.path()));
										break;
									}
									case hashpp::ALGORITHMS::SHA2_384: {
										vSHA2_384.push_back(hashpp::SHA::SHA2_384().getHash(item.path()));
										break;
									}
									case hashpp::ALGORITHMS::SHA2_512: {
										vSHA2_512.push_back(hashpp::SHA::SHA2_512().getHash(item.path()));
										break;
									}
									case hashpp::ALGORITHMS::SHA2_512_224: {
										vSHA2_512_224.push_back(hashpp::SHA::SHA2_512_224().getHash(item.path()));
										break;
									}
									case hashpp::ALGORITHMS::SHA2_512_256: {
										vSHA2_512_256.push_back(hashpp::SHA::SHA2_512_256().getHash(item.path()));
										break;
									}
								}
							}
						}
					}
				}
			}
			return hashCollection{
				{
					{ "MD5", vMD5 },
					{ "MD4", vMD4 },
					{ "MD2", vMD2 },
					{ "SHA1", vSHA1 },
					{ "SHA2-224", vSHA2_224 },
					{ "SHA2-256", vSHA2_256 },
					{ "SHA2-384", vSHA2_384 },
					{ "SHA2-512", vSHA2_512 },
					{ "SHA2-512-224", vSHA2_512_224 },
					{ "SHA2-512-256", vSHA2_512_256 }
				}
			};
		}
	};
}

#endif
