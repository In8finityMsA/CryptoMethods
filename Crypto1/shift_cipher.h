#pragma once
#include "icipher.h"
#include <string>

class ShiftCipher : public ICipher<std::string, size_t> {
	typedef std::string::value_type Character;
public: 
	ShiftCipher(Character char_key, const std::string& alphabet = "ÀÁÂÃÄÅ¨ÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞß ") {
		if (alphabet.length() == 0) {
			throw std::invalid_argument("Alphabet is zero length.");
		}
		this->alphabet = alphabet;
		key = FindInAlphabet(char_key) + 1;
	}

	std::string Decrypt(const std::string& ciphertext) const override {
		std::string out;
		out.reserve(ciphertext.length());
		for (size_t i = 0; i < ciphertext.length(); i++) {
			auto index = FindInAlphabet(ciphertext[i]);
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
			auto index = FindInAlphabet(text[i]);
			index = index + key < alphabet.length() ? index + key : key + index - alphabet.length();
			Character encrypted_char = alphabet[ index ];
			out.push_back(encrypted_char);
		}
		return out;
	}

private:
	size_t FindInAlphabet(Character c) const {
		auto alphabet_position = alphabet.find(c);
		if (alphabet_position == std::string::npos) {
			throw std::invalid_argument("Cannot find a character in the alphabet.");
		}
		return alphabet_position;
	}
};