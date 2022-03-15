#pragma once
#include "../Interface/icipher.h"
#include <utility>

class AffineCipher : public ICipher {
public:
	AffineCipher(std::string string_key, const std::string& alphabet = "ÀÁÂÃÄÅ¨ÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞß ") {
		if (alphabet.length() == 0) {
			throw std::invalid_argument("Alphabet is zero length.");
		}
		InitAlphabetIndex(alphabet);
		this->alphabet = alphabet;

		if (string_key.length() != 2) {
			throw std::invalid_argument("Key length must be two.");
		}
		key.first = FindInAlphabetIndex(string_key[0]);
		if (GCD(alphabet.length(), key.first) != 1) {
			throw std::invalid_argument("First part of a key and alphabet length are not coprime.");
		}
		key.second = FindInAlphabetIndex(string_key[1]);

		euler_m = Euler(alphabet.length());
		inverse = Inverse(key.first, alphabet.length());
	}

	std::string Decrypt(const std::string& ciphertext) const override {
		std::string out;
		out.reserve(ciphertext.length());
		for (size_t i = 0; i < ciphertext.length(); i++) {
			auto index = FindInAlphabetIndex(ciphertext[i]);
			index = index >= key.second ? index - key.second : alphabet.length() - key.second + index;
			Character decrypted_char = alphabet[inverse * index % alphabet.length()];
			out.push_back(decrypted_char);
		}
		return out;
	}

	std::string Encrypt(const std::string& text) const override {
		std::string out;
		out.reserve(text.length());
		for (size_t i = 0; i < text.length(); i++) {
			auto index = FindInAlphabetIndex(text[i]);
			Character encrypted_char = alphabet[(key.first * index + key.second) % alphabet.length() ];
			out.push_back(encrypted_char);
		}
		return out;
	}

private:
	std::pair<size_t, size_t> key;
	size_t euler_m;
	size_t inverse;

	size_t GCD(size_t a, size_t b) {
		while (b != 0) {
			a = a % b;
			std::swap(a, b);
		}
		return a;
	}

	size_t Inverse(size_t a, size_t m) {
		return Binpow(a, euler_m - 1, m);
	}

	size_t Binpow(size_t a, size_t n, size_t m) {
		size_t res = 1;
		while (n) {
			if (n & 1)
				res = res * a % m;
			a = a * a % m;
			n >>= 1;
		}
		return res;
	}

	size_t Euler(size_t n) {
		int result = n;
		for (int i = 2; i * i <= n; ++i)
			if (n % i == 0) {
				while (n % i == 0)
					n /= i;
				result -= result / i;
			}
		if (n > 1)
			result -= result / n;
		return result;
	}
};