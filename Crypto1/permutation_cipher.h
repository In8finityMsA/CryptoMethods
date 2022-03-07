#pragma once
#include "icipher.h"
#include <string>
#include <stdexcept>
#include <vector>
#include <map>
#include <algorithm>

class PermutationCipher : public ICipher<std::string, std::vector<size_t>> {
	typedef std::string::value_type Character;
public:
	PermutationCipher(std::string string_key, const std::string& alphabet = "ÀÁÂÃÄÅ¨ÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞß ") {
		if (alphabet.length() == 0) {
			throw std::invalid_argument("Alphabet is zero length.");
		}
		this->alphabet = alphabet;

		for (size_t i = 0; i < alphabet.length(); i++) {
			auto result = index_alphabet.insert({ alphabet[i], i });
			if (!result.second) {
				throw std::invalid_argument("Alphabet symbols are not unique.");
			}
		}

		if (string_key.length() > alphabet.length()) {
			throw std::invalid_argument("Key length is greater than alphabet length.");
		}
		std::vector<std::pair<size_t, size_t>> permut;
		permut.reserve(string_key.length());
		for (size_t i = 0; i < string_key.length(); i++) {
			permut.push_back({FindInAlphabetIndex(string_key[i]), i});
		}

		sort(permut.begin(), permut.end());
		key.resize(permut.size());
		for (int i = 0; i < permut.size(); i++) {
			if (i != 0 && permut[i].first == permut[i - 1].first) {
				throw std::invalid_argument("Key contains equal characters.");
			}
			key[permut[i].second] = i;
		}
	}

	std::string Decrypt(const std::string& ciphertext) const override {
		if (ciphertext.length() % key.size() != 0) {
			throw std::invalid_argument("Ciphertext length is not divisible by block size.");
		}

		std::string out;
		out.resize(ciphertext.length());
		size_t block_begin = 0;
		for (size_t k = 0; k < ciphertext.length() / key.size(); k++) {
			for (size_t i = 0; i < key.size(); i++) {
				out[block_begin + i] = ciphertext[block_begin + key[i]];
			}
			block_begin += key.size();
		}
		return out;
	}

	std::string Encrypt(const std::string& text) const override {
		std::string in = text;
		std::string out;
		if (in.length() % key.size()) {
			auto padding = key.size() - in.length() % key.size();
			in.append(padding, 'A');
		}

		out.resize(in.length());
		size_t block_begin = 0;
		for (size_t k = 0; k < in.length() / key.size(); k++) {
			for (size_t i = 0; i < key.size(); i++) {
				out[block_begin + key[i]] = in[block_begin + i];
			}
			block_begin += key.size();
		}
		return out;
	}

private:
	std::map<Character, size_t> index_alphabet;

	size_t FindInAlphabetIndex(Character c) const {
		auto iter = index_alphabet.find(c);
		if (iter == index_alphabet.end()) {
			throw std::invalid_argument("Cannot find a character in the alphabet.");
		}
		return iter->second;
	}
};