#pragma once
#include <string>
#include <stdexcept>
#include <map>

class ICipher {
protected:
	typedef std::string::value_type Character;
public:
	ICipher() {};
	virtual ~ICipher() = default;

	virtual std::string Decrypt(const std::string& ciphertext) const = 0;
	virtual std::string Encrypt(const std::string& text) const = 0;

protected:
	std::string alphabet{};
	std::map<Character, size_t> index_alphabet;

	size_t FindInAlphabetIndex(Character c) const {
		auto iter = index_alphabet.find(c);
		if (iter == index_alphabet.end()) {
			throw std::invalid_argument("Cannot find a character in the alphabet.");
		}
		return iter->second;
	}

	void InitAlphabetIndex(const std::string& alphabet) {
		for (size_t i = 0; i < alphabet.length(); i++) {
			auto result = index_alphabet.insert({ alphabet[i], i });
			if (!result.second) {
				throw std::invalid_argument("Alphabet symbols are not unique.");
			}
		}
	}
};