#pragma once
#include "../Interface/icipher.h"

class ShiftCipher : public ICipher {
public: 
	ShiftCipher(std::string string_key, const std::string& alphabet = "ÀÁÂÃÄÅ¨ÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞß ") {
		if (alphabet.length() == 0) {
			throw std::invalid_argument("Alphabet is zero length.");
		}
		InitAlphabetIndex(alphabet);
		this->alphabet = alphabet;

		if (string_key.length() != 1) {
			throw std::invalid_argument("Key length must be one.");
		}
		key = FindInAlphabetIndex(string_key[0]);
	}

	std::string Decrypt(const std::string& ciphertext) const override {
		std::string out;
		out.reserve(ciphertext.length());
		for (size_t i = 0; i < ciphertext.length(); i++) {
			auto index = FindInAlphabetIndex(ciphertext[i]);
			index = index >= key ? index - key : alphabet.length() - key + index;
			Character decrypted_char = alphabet[ index ];
			out.push_back(decrypted_char);
		}
		return out;
	}

	std::string Encrypt(const std::string& text) const override {
		std::string out;
		out.reserve(text.length());
		for (size_t i = 0; i < text.length(); i++) {
			auto index = FindInAlphabetIndex(text[i]);
			index = index + key < alphabet.length() ? index + key : key + index - alphabet.length();
			Character encrypted_char = alphabet[ index ];
			out.push_back(encrypted_char);
		}
		return out;
	}

private:
	size_t key;
	std::map<Character, size_t> index_alphabet;

	size_t FindInAlphabetIndex(Character c) const {
		auto iter = index_alphabet.find(c);
		if (iter == index_alphabet.end()) {
			throw std::invalid_argument("Cannot find a character in the alphabet.");
		}
		return iter->second;
	}
};