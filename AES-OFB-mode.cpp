#include <iostream>
#include <chrono>

#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

std::string aes_ofb_mode_encrypt(std::string &plain, CryptoPP::SecByteBlock key, CryptoPP::byte *iv) {
    std::string cipher;
    std::string output;

    try {
        CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption e(key, key.size(), iv);

        CryptoPP::StringSource(plain, true,
            new CryptoPP::StreamTransformationFilter(e,
                new CryptoPP::StringSink(cipher)
            ) //StreamTransformationFilter
        ); // StringSource
    } catch (CryptoPP::Exception &exception) {
        std::cerr << exception.what() << std::endl;
        exit(1);
    }

    CryptoPP::StringSource(cipher, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(output)
        ) // HexEncoder
    ); // StringSource
    return output;
}

std::string aes_ofb_mode_decrypt(std::string &encoded, CryptoPP::SecByteBlock key, CryptoPP::byte *iv) {
    std::string cipher;
    std::string output;

    CryptoPP::StringSource(encoded, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::StringSink(cipher)
        ) //HexDecoder
    ); //StringSource

    try {
        CryptoPP::OFB_Mode<CryptoPP::AES>::Decryption d(key, key.size(), iv);
        CryptoPP::StringSource(cipher, true,
            new CryptoPP::StreamTransformationFilter(d,
                new CryptoPP::StringSink(output)
            ) //StreamTransformationFilter
        ); //StringSource
    } catch (CryptoPP::Exception &exception) {
        std::cerr << exception.what() << std::endl;
        exit(1);
    }
    return output;
}

int main() {
    std::string msg1 = "Lorem ipsum dolor sit amet conse";
    std::string msg2 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim,";
    std::string msg3 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, m";
    std::string msg4 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, maxime deleniti harum aperiam molestias animi quam assumenda ipsam repellat earum ab quae. Lorem ipsum dolor sit amet consectetur";
    std::string msg5 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, maxime deleniti harum aperiam molestias animi quam assumenda ipsam repellat earum ab quae. Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, maxime deleniti harum aperiam molestias animi quam assumenda ipsam repellat earum ab quae. Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exerci";
    std::string cipher;

    std::chrono::_V2::system_clock::time_point start, end;
    std::chrono::microseconds duration;

    CryptoPP::AutoSeededRandomPool rnd;
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    rnd.GenerateBlock(key, key.size());
    CryptoPP::byte iv[ CryptoPP::AES::BLOCKSIZE ];
    rnd.GenerateBlock(iv, sizeof(iv));

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        cipher = aes_ofb_mode_encrypt(msg1, key, iv);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Message: " << msg1 << std::endl;
    std::cout << "Cipher: " << cipher << std::endl;
    std::cout << "Input 256 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        cipher = aes_ofb_mode_encrypt(msg2, key, iv);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Message: " << msg2 << std::endl;
    std::cout << "Cipher: " << cipher << std::endl;
    std::cout << "Input 512 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        cipher = aes_ofb_mode_encrypt(msg3, key, iv);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Message: " << msg3 << std::endl;
    std::cout << "Cipher: " << cipher << std::endl;
    std::cout << "Input 1024 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        cipher = aes_ofb_mode_encrypt(msg4, key, iv);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Message: " << msg4 << std::endl;
    std::cout << "Cipher: " << cipher << std::endl;
    std::cout << "Input 2048 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        cipher = aes_ofb_mode_encrypt(msg5, key, iv);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Message: " << msg5 << std::endl;
    std::cout << "Cipher: " << cipher << std::endl;
    std::cout << "Input 4096 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    std::cout << "########### decryption" << std::endl;
    std::string recovered;

    std::string cipher1 = aes_ofb_mode_encrypt(msg1, key, iv);
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        recovered = aes_ofb_mode_decrypt(cipher1, key, iv);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Recovered: " << recovered << std::endl << std::endl;
    std::cout << "Input 256 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    std::string cipher2 = aes_ofb_mode_encrypt(msg2, key, iv);
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        recovered = aes_ofb_mode_decrypt(cipher2, key, iv);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Recovered: " << recovered << std::endl << std::endl;
    std::cout << "Input 512 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    std::string cipher3 = aes_ofb_mode_encrypt(msg3, key, iv);
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        recovered = aes_ofb_mode_decrypt(cipher3, key, iv);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Recovered: " << recovered << std::endl << std::endl;
    std::cout << "Input 1024 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    std::string cipher4 = aes_ofb_mode_encrypt(msg4, key, iv);
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        recovered = aes_ofb_mode_decrypt(cipher4, key, iv);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Recovered: " << recovered << std::endl << std::endl;
    std::cout << "Input 2048 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    std::string cipher5 = aes_ofb_mode_encrypt(msg5, key, iv);
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        recovered = aes_ofb_mode_decrypt(cipher5, key, iv);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Recovered: " << recovered << std::endl << std::endl;
    std::cout << "Input 4096 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;
}