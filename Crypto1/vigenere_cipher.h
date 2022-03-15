#pragma once
#include "icipher.h"
#include <string>
#include <stdexcept>
#include <map>
#include <vector>

class VigenereCipher : public ICipher {
public:
	VigenereCipher(std::string string_key, const std::string& alphabet = "ÀÁÂÃÄÅ¨ÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞß ") {
		if (alphabet.length() == 0) {
			throw std::invalid_argument("Alphabet is zero length.");
		}
		InitAlphabetIndex(alphabet);
		this->alphabet = alphabet;
		
		key.reserve(string_key.length());
		for (size_t i = 0; i < string_key.length(); i++) {
			key.push_back(FindInAlphabetIndex(string_key[i]));
		}
	}

	std::string Decrypt(const std::string& ciphertext) const override {
		std::string out;
		out.reserve(ciphertext.length());

		for (int i = 0, j = 0; i < ciphertext.length(); ++j, ++i) {
			if (j == key.size()) {
				j = 0;
			}
			auto index = FindInAlphabetIndex(ciphertext[i]);
			index = index >= key[j] ? index - key[j] : alphabet.length() - key[j] + index;
			out.push_back(alphabet[index]);
		}
		return out;
	}

	std::string Encrypt(const std::string& text) const override {
		std::string out;
		out.reserve(text.length());

		for (int i = 0, j = 0; i < text.length(); ++j, ++i) {
			if (j == key.size()) {
				j = 0; 
			}
			out.push_back(alphabet[ (FindInAlphabetIndex(text[i]) + key[j]) % alphabet.length() ]);
		}
		return out;
	}

private:
	std::vector<size_t> key;
};