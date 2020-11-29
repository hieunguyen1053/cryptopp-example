#include <iostream>
#include <cryptopp/dsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>

std::string DSA_createSignature(std::string message, CryptoPP::AutoSeededRandomPool &prng, CryptoPP::DL_Keys_DSA::PrivateKey privateKey) {
    std::string signature;
    std::string output;

    CryptoPP::DSA::Signer signer(privateKey);
    CryptoPP::StringSource(message, true,
        new CryptoPP::SignerFilter(prng, signer,
            new CryptoPP::StringSink(signature)
        ) //SignerFilter
    ); //StringSource

    CryptoPP::StringSource(signature, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(output)
        ) //HexEncoder
    ); //StringSource
    return output;
}

bool DSA_verifySignature(std::string message, std::string signature, CryptoPP::DL_Keys_DSA::PublicKey publicKey) {
    std::string decoded;
    std::string output;
    bool result = false;

    CryptoPP::StringSource(signature, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::StringSink(decoded)
        ) //StringSink
    ); //StringSource

    CryptoPP::DSA::Verifier verifier(publicKey);
    CryptoPP::StringSource(message+decoded, true,
        new CryptoPP::SignatureVerificationFilter(
            verifier,
            new CryptoPP::ArraySink((CryptoPP::byte*) &result, sizeof(result)),
                CryptoPP::SignatureVerificationFilter::PUT_RESULT | CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_END
        ) //SignatureVerificationFilter
    ); //StringSource
    return result;
}

int main() {
    std::string msg1 = "Lorem ipsum dolor sit amet conse";
    std::string msg2 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim,";
    std::string msg3 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, m";
    std::string msg4 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, maxime deleniti harum aperiam molestias animi quam assumenda ipsam repellat earum ab quae. Lorem ipsum dolor sit amet consectetur";
    std::string msg5 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, maxime deleniti harum aperiam molestias animi quam assumenda ipsam repellat earum ab quae. Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, maxime deleniti harum aperiam molestias animi quam assumenda ipsam repellat earum ab quae. Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exerci";
    std::string signature;

    std::chrono::_V2::system_clock::time_point start, end;
    std::chrono::microseconds duration;

    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::DSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(prng, 2048);

    CryptoPP::DSA::PublicKey publicKey;
    publicKey.AssignFrom(privateKey);

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        signature = DSA_createSignature(msg1, prng, privateKey);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Message: " << msg1 << std::endl;
    std::cout << "Signature: " << signature << std::endl;
    std::cout << "Input 256 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        signature = DSA_createSignature(msg2, prng, privateKey);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Message: " << msg2 << std::endl;
    std::cout << "Signature: " << signature << std::endl;
    std::cout << "Input 512 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        signature = DSA_createSignature(msg3, prng, privateKey);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Message: " << msg3 << std::endl;
    std::cout << "Signature: " << signature << std::endl;
    std::cout << "Input 1024 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        signature = DSA_createSignature(msg4, prng, privateKey);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Message: " << msg4 << std::endl;
    std::cout << "Signature: " << signature << std::endl;
    std::cout << "Input 2048 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        signature = DSA_createSignature(msg5, prng, privateKey);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Message: " << msg5 << std::endl;
    std::cout << "Signature: " << signature << std::endl;
    std::cout << "Input 4096 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    signature = DSA_createSignature(msg1, prng, privateKey);
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        if (DSA_verifySignature(msg1, signature, publicKey) == true) {
            // std::cout << "Verified signature on message" << std::endl;
        }
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Input 256 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    signature = DSA_createSignature(msg2, prng, privateKey);
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        if (DSA_verifySignature(msg2, signature, publicKey) == true) {
            // std::cout << "Verified signature on message" << std::endl;
        }
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Input 512 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    signature = DSA_createSignature(msg3, prng, privateKey);
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        if (DSA_verifySignature(msg3, signature, publicKey) == true) {
            // std::cout << "Verified signature on message" << std::endl;
        }
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Input 1024 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    signature = DSA_createSignature(msg4, prng, privateKey);
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        if (DSA_verifySignature(msg4, signature, publicKey) == true) {
            // std::cout << "Verified signature on message" << std::endl;
        }
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Input 2048 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    signature = DSA_createSignature(msg5, prng, privateKey);
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        if (DSA_verifySignature(msg5, signature, publicKey) == true) {
            // std::cout << "Verified signature on message" << std::endl;
        }
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Input 4096 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    return 0;
}