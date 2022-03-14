#pragma once

class ICipher {
protected:
	typedef std::string::value_type Character;
public:
	ICipher() {};
	virtual ~ICipher() = default;

	virtual std::string Decrypt(const std::string& ciphertext) const = 0;
	virtual std::string Encrypt(const std::string& text) const = 0;

protected:
	std::string  alphabet{};
};