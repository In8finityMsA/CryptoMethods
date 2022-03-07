#pragma once

template <typename TextType, typename KeyType>
class ICipher {
public:
	ICipher() {};
	ICipher(KeyType key, TextType alphabet) : key(key), alphabet(alphabet) {}
	virtual ~ICipher() = default;

	virtual TextType Decrypt(const TextType& ciphertext) const = 0;
	virtual TextType Encrypt(const TextType& text) const = 0;

protected:
	KeyType key{};
	TextType alphabet{};
};