#pragma once
#include "icipher.h"
#include <string>
#include <stdexcept>
#include <array>
#include <map>

class HillCipher : public ICipher {
	typedef std::array<std::array<int, 2>, 2> Matrix2;
public:
	HillCipher(std::string string_key, const std::string& alphabet = "ÀÁÂÃÄÅ¨ÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞß ") {
		if (alphabet.length() == 0) {
			throw std::invalid_argument("Alphabet is zero length.");
		}
		if (string_key.length() != 4) {
			throw std::invalid_argument("Key length must be four.");
		}
		this->alphabet = alphabet;
		
		for (size_t i = 0; i < alphabet.length(); i++) {
			auto result = index_alphabet.insert({ alphabet[i], i });
			if (!result.second) {
				throw std::invalid_argument("Alphabet symbols are not unique.");
			}
		}

		key[0][0] = FindInAlphabetIndex(string_key[0]);
		key[0][1] = FindInAlphabetIndex(string_key[1]);
		key[1][0] = FindInAlphabetIndex(string_key[2]);
		key[1][1] = FindInAlphabetIndex(string_key[3]);
		if (GCD(abs(key[0][0] * key[1][1] - key[0][1] * key[1][0]), alphabet.length()) != 1) { // Check gcd
			throw std::invalid_argument("Determinant of a key must be coprime with alphabet length.");
		}
		if ((key[0][0] * key[1][1] - key[0][1] * key[1][0]) % alphabet.length() == 0) { // Check divisibility
			throw std::invalid_argument("Determinant is divisible by alphabet length.");
		}
		inverse_key = Inverse_Matrix2(key, alphabet.length());
	}

	std::string Decrypt(const std::string& ciphertext) const override {
		std::string out;
		out.reserve(ciphertext.length());

		for (size_t i = 0; i < ciphertext.length(); i += 2) {
			for (size_t j = 0; j < 2; j++) {
				int mult = 0;
				for (size_t k = 0; k < 2; k++) {
					mult += inverse_key[j][k] * FindInAlphabetIndex(ciphertext[i + k]);
				}
				out.push_back(alphabet[mult % alphabet.length()]);
			}
		}
		return out;
	}

	std::string Encrypt(const std::string& text) const override {
		std::string out;
		bool is_odd = text.length() % 2 == 1;

		out.reserve(text.length() + is_odd);
		
		for (size_t i = 0; i < text.length(); i += 2) {
			for (size_t j = 0; j < 2; j++) {
				int mult = 0;
				for (size_t k = 0; k < 2; k++) {
					mult += key[j][k] * FindInAlphabetIndex(text[i + k]);
				}
				out.push_back(alphabet[mult % alphabet.length()]);
			}
		}
		return out;
	}

private:
	Matrix2 key;
	Matrix2 inverse_key;
	std::map<Character, size_t> index_alphabet;


	size_t FindInAlphabetIndex(Character c) const {
		auto iter = index_alphabet.find(c);
		if (iter == index_alphabet.end()) {
			throw std::invalid_argument("Cannot find a character in the alphabet.");
		}
		return iter->second;
	}

	Matrix2 Inverse_Matrix2(Matrix2 matrix, int mod) {
		int det = matrix[0][0] * matrix[1][1] - matrix[1][0] * matrix[0][1];
		int inv_det = Inverse(ModPositive(det, mod), mod);
		return { ModPositive(matrix[1][1] * inv_det, mod), ModPositive(-matrix[0][1] * inv_det, mod),
				ModPositive(-matrix[1][0] * inv_det, mod),  ModPositive(matrix[0][0] * inv_det, mod) };
	}

	inline int ModPositive(int a, int m) {
		a %= m;
		return a < 0 ? a + m : a;
	}

	size_t GCD(size_t a, size_t b) {
		while (b != 0) {
			a = a % b;
			std::swap(a, b);
		}
		return a;
	}

	size_t Inverse(size_t a, size_t m) {
		return Binpow(a, Euler(m) - 1, m);
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