#pragma once
#include <istream>
#include "../Cipher/ciphers.h"
#include "../Interface/icipher.h"

const char* const cipher_types[] = { "Shift", "Affine", "Substitution", "Permutation", "Hill", "Vigenere" };

class CipherInitializer {
public:
	static ICipher* InitCipher(const std::string& cipher_name, std::istream& stream_key, std::istream* stream_alphabet = nullptr) {
		if (!stream_key.good()) {
			throw std::invalid_argument("Failed reading from key file.");
		}

		std::string key;
		std::getline(stream_key, key);
		if (stream_alphabet == nullptr) {
			return ChooseCipher(cipher_name, key);
		} else {
			if (!stream_alphabet->good()) {
				throw std::invalid_argument("Failed reading from alphabet file.");
			}
			std::string alphabet;
			std::getline(*stream_alphabet, alphabet);
			return ChooseCipher(cipher_name, key, alphabet);
		}
	}

private:
	static ICipher* ChooseCipher(const std::string& cipher_name, const std::string& key) {
		if (0 == strcmp(cipher_name.c_str(), cipher_types[0])) {
			return new ShiftCipher(key);
		} else if (0 == strcmp(cipher_name.c_str(), cipher_types[1])) {
			return new AffineCipher(key);
		} else if (0 == strcmp(cipher_name.c_str(), cipher_types[2])) {
			return new SubstitutionCipher(key);
		} else if (0 == strcmp(cipher_name.c_str(), cipher_types[3])) {
			return new PermutationCipher(key);
		} else if (0 == strcmp(cipher_name.c_str(), cipher_types[4])) {
			return new HillCipher(key);
		} else if (0 == strcmp(cipher_name.c_str(), cipher_types[5])) {
			return new VigenereCipher(key);
		}
	}

	static ICipher* ChooseCipher(const std::string& cipher_name, const std::string& key, const std::string& alphabet) {
		if (0 == strcmp(cipher_name.c_str(), cipher_types[0])) {
			return new ShiftCipher(key, alphabet);
		} else if (0 == strcmp(cipher_name.c_str(), cipher_types[1])) {
			return new AffineCipher(key, alphabet);
		} else if (0 == strcmp(cipher_name.c_str(), cipher_types[2])) {
			return new SubstitutionCipher(key, alphabet);
		} else if (0 == strcmp(cipher_name.c_str(), cipher_types[3])) {
			return new PermutationCipher(key, alphabet);
		} else if (0 == strcmp(cipher_name.c_str(), cipher_types[4])) {
			return new HillCipher(key, alphabet);
		} else if (0 == strcmp(cipher_name.c_str(), cipher_types[5])) {
			return new VigenereCipher(key, alphabet);
		}
	}
};