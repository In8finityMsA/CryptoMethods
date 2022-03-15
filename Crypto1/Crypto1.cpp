#include <iostream>
#include <fstream>
#include "Tools/CipherInitializer.h"
#include <clocale>
#include <memory>

const char usage_string[] = "Usage: Crypto.exe <cipher type> <-e | -d> <key file> <input file> <output file> [alphabet file]";

enum class CommandMode {
    Encrypt,
    Decrypt
};

int main(int argc, char** argv)
{
    setlocale(LC_ALL, "RU");
    if (argc < 6 || argc > 7) {
        std::cerr << "Wrong number of arguments." << usage_string;
        return -1;
    }

    CommandMode mode;
    if (0 == strcmp(argv[2], "-e")) {
        mode = CommandMode::Encrypt;
    } else if (0 == strcmp(argv[2], "-d")) {
        mode = CommandMode::Decrypt;
    } else {
        std::cerr << "Invalid flag: " << argv[2] << ". Accept only -e for encrypt or -d for decrypt.";
    }

    std::ifstream key_in(argv[3]);
    if (!key_in.good()) {
        std::cerr << "Can't open file " << argv[3] << std::endl;
        return -1;
    }

    std::ifstream text_in(argv[4]);
    if (!text_in.good()) {
        std::cerr << "Can't open file " << argv[4] << std::endl;
        return -1;
    }

    std::ifstream alphabet_in;
    if (argc == 7) {
        alphabet_in.open(argv[6]);
        if (!alphabet_in.good()) {
            std::cerr << "Can't open file " << argv[6] << std::endl;
            return -1;
        }
    }

    std::string text;
    std::getline(text_in, text);
    try {
        std::unique_ptr<ICipher> cipher;
        if (alphabet_in.is_open()) {
            cipher = std::unique_ptr<ICipher>(CipherInitializer::InitCipher(argv[1], key_in, &alphabet_in));
        } else {
            cipher = std::unique_ptr<ICipher>(CipherInitializer::InitCipher(argv[1], key_in));
        }

        std::string out;
        switch (mode) {
        case CommandMode::Encrypt:
            out = cipher->Encrypt(text);
            break;
        case CommandMode::Decrypt:
            out = cipher->Decrypt(text);
            break;
        }

        std::ofstream output(argv[5]);
        output << out;
    }
    catch (std::invalid_argument& e) {
        std::cerr << e.what();
    }
    catch (std::exception& exc) {
        std::cerr << exc.what();
    }

    
    //std::string str = "ÏÐÈÂÅÒÎÌÅÄÂÅÄÎÀÁÂÃÄÅ¨ÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßÊ";
    //try {
    //    VigenereCipher shift_crypto{ "ÍÀÈÓÈÐÀÃÛÈÓÎÑËÈÂÈÐÈÎÛÌÓÙÛÔÙÑÒÛÈÂÍÑ×ØÖÒÖÂÒÛÓÉÇßÒÂÜÓËÛÐÓÈÂÐÛÌÍÓ", "ÀÁÂÃÄÅ¨ÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞß" };
    //    
    //    std::cout << "String: " << str << std::endl;
    //    std::string result = shift_crypto.Encrypt(str);
    //    std::cout << "result: " << result << std::endl;
    //    std::string source = shift_crypto.Decrypt(result);
    //    std::cout << "string: " << source << std::endl;
    //} 
    //catch (std::invalid_argument& e) {
    //    std::cerr << e.what();
    //}
    //catch (std::exception& exc) {
    //    std::cerr << exc.what();
    //}

    return 0;
}
