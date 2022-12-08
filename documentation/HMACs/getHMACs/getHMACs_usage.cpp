/*

	Basic usage of Hash++ getHMACs method.
		This file shows basic usage of the above described method
		and its overloads, as well as how data can be extracted
		from its returned object.
		
*/

#include "hashpp.h"

using namespace hashpp;

int main() {
	// create HMAC_DataContainer object
	// to store algorithm to use, key, 
	// and data to HMAC
	HMAC_DataContainer hmac_container;
	
	// set algorithm to use
	hmac_container.setAlgorithm(ALGORITHMS::SHA2_256);
	
	// set key to use
	hmac_container.setKey("secretKey");

	// set data to HMAC
	hmac_container.setData("dataToHMAC1", "dataToHMAC2", "dataToHMAC3");

	// calculate the HMACs for all data in container
	// using key and algorithm specified
	hashCollection hmacs = get::getHMACs(hmac_container);

	// parse and print each HMAC
	for (auto& hmac : hmacs["SHA2-256"]) {
		std::cout << hmac << std::endl;
	}
	
	// output:
	//   f0dfad2b51176704f8fff07e2c6063417b1d361465b4f9eaacf9b756037bb815
	//   bf912338f4c9d21eff351d085a26b9723eb0da6582039d18a003046c3ae3fbef
	//   abba2bd3400c1b03322fac45539462241ca6ae14a81d58e1db017a9bcb3947b2
}
