#pragma once
#include "icipher.h"
#include <string>
#include <stdexcept>

class SubstitutionCipher : public ICipher {
public:
	SubstitutionCipher(std::string string_key, const std::string& alphabet = "ÀÁÂÃÄÅ¨ÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞß ") {
		if (alphabet.length() == 0) {
			throw std::invalid_argument("Alphabet is zero length.");
		}
		this->alphabet = alphabet;

		if (alphabet.length() != string_key.length()) {
			throw std::invalid_argument("Key is not the same length as an alphabet");
		}

		for (size_t i = 0; i < string_key.length(); i++) {
			auto result = encrypt_map.insert({ alphabet[i], string_key[i] });
			decrypt_map.insert({ string_key[i], alphabet[i] });
			if (!result.second) {
				throw std::invalid_argument("Alphabet symbols are not unique");
			}
		}
		for (size_t i = 0; i < alphabet.length(); i++) {
			if (decrypt_map.find(alphabet[i]) == decrypt_map.end()) {
				throw std::invalid_argument("Substitution is malformed (not a bijection)");
			}
		}
	}

	std::string Decrypt(const std::string& ciphertext) const override {
		std::string out;
		out.reserve(ciphertext.length());
		for (size_t i = 0; i < ciphertext.length(); i++) {
			Character decrypted_char = decrypt_map.at(ciphertext[i]);
			out.push_back(decrypted_char);
		}
		return out;
	}

	std::string Encrypt(const std::string& text) const override {
		std::string out;
		out.reserve(text.length());
		for (size_t i = 0; i < text.length(); i++) {
			Character encrypted_char = encrypt_map.at(text[i]);
			out.push_back(encrypted_char);
		}
		return out;
	}

private:
	std::string key;
	std::map<Character, Character> encrypt_map;
	std::map<Character, Character> decrypt_map;
};