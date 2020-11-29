#include <iostream>
#include <chrono>

#include <cryptopp/cryptlib.h>
#include <cryptopp/sha3.h>
#include <cryptopp/hex.h>

std::string sha3(std::string &input) {
    CryptoPP::SHA3_256 hash;

    std::string digest;
    std::string output;

    CryptoPP::StringSource(input, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::StringSink(digest)
        ) //HashFilter
    ); //StringSource

    CryptoPP::StringSource(digest, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(output)
        )
    ); //StringSource

    return output;
}

int main() {
    std::string msg1 = "Lorem ipsum dolor sit amet conse";
    std::string msg2 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim,";
    std::string msg3 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, m";
    std::string msg4 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, maxime deleniti harum aperiam molestias animi quam assumenda ipsam repellat earum ab quae. Lorem ipsum dolor sit amet consectetur";
    std::string msg5 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, maxime deleniti harum aperiam molestias animi quam assumenda ipsam repellat earum ab quae. Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, maxime deleniti harum aperiam molestias animi quam assumenda ipsam repellat earum ab quae. Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exerci";
    std::string digest;

    std::chrono::_V2::system_clock::time_point start, end;
    std::chrono::microseconds duration;

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        digest = sha3(msg1);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Message: " << msg1 << std::endl;
    std::cout << "Digest: " << digest << std::endl;
    std::cout << "Input 256 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        digest = sha3(msg2);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Message: " << msg2 << std::endl;
    std::cout << "Digest: " << digest << std::endl;
    std::cout << "Input 512 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        digest = sha3(msg3);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Message: " << msg3 << std::endl;
    std::cout << "Digest: " << digest << std::endl;
    std::cout << "Input 1024 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        digest = sha3(msg4);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Message: " << msg4 << std::endl;
    std::cout << "Digest: " << digest << std::endl;
    std::cout << "Input 2048 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        digest = sha3(msg5);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Message: " << msg5 << std::endl;
    std::cout << "Digest: " << digest << std::endl;
    std::cout << "Input 4096 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;
    return 0;
}