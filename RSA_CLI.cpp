// Debug:
// g++ -g -ggdb -O0 -Wall -Wextra -Wno-unused -Wno-type-limits -I. -I/usr/include/cryptopp cryptopp-key-gen.cpp -o cryptopp-key-gen.exe -lcryptopp

// Release:
// g++ -O2 -Wall -Wextra -Wno-unused -Wno-type-limits -I. -I/usr/include/cryptopp cryptopp-key-gen.cpp -o cryptopp-key-gen.exe -lcryptopp && strip --strip-all cryptopp-key-gen.exe

// This version use g++, compiled on Windows 11

#ifdef _WIN32
#include <windows.h>
#endif
#include <cstdlib>
#include <locale>
#include <cctype>

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;
using std::stoi;

#include <stdexcept>
using std::runtime_error;

//CryptoPP


#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;


#include "cryptopp/rsa.h"
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::ArraySink;
using CryptoPP::ArraySource;

using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include <cryptopp/cryptlib.h>
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

// DER - Binary
void SavePrivateKey(const string& filename, const PrivateKey& key);
void SavePublicKey(const string& filename, const PublicKey& key);

void LoadPrivateKey(const string& filename, PrivateKey& key);
void LoadPublicKey(const string& filename, PublicKey& key);

// PEM - B64
void SaveBase64PrivateKey(const string& filename, const PrivateKey& key);
void SaveBase64PublicKey(const string& filename, const PublicKey& key);

void SaveBase64(const string& filename, const BufferedTransformation& bt);

void LoadBase64PrivateKey(const string& filename, PrivateKey& key);
void LoadBase64PublicKey(const string& filename, PublicKey& key);

void LoadBase64(const string& filename, BufferedTransformation& bt);

// General, used in both DER and PEM
void Save(const string& filename, const BufferedTransformation& bt);
void Load(const string& filename, BufferedTransformation& bt);

// KeyGen DER and B64 supported
void KeyGen(const char* keyFormat, const int& keySize, const char* privateFile, const char* publicFile)
{
    AutoSeededRandomPool rng;

    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, keySize);

    RSA::PublicKey publicKey(privateKey);

    if (!strcmp(keyFormat, "DER"))
    {
        SavePrivateKey(privateFile, privateKey);
        SavePublicKey(publicFile, publicKey);
        
    } else if (!strcmp(keyFormat, "PEM"))
    {
        SaveBase64PrivateKey(privateFile, privateKey);
        SaveBase64PublicKey(publicFile, publicKey);
    } else
    {
        cout << "Invalid key format, only DER or PEM are accepted" << endl;
        exit(1);
    }
    
    cout << "Key has been generated in " << keyFormat <<" format and saved to:" << endl;
    cout << "\tPrivate file: "<< privateFile << endl;
    cout << "\tPublic file: " << publicFile << endl;
}



// Encrypt DER
void Encrypt(const char* keyFormat, const char* publicFile, const char* plainTextFile, const char* cipherTextFile)
{
    RSA::PublicKey publicKey;
    AutoSeededRandomPool rng;

    if (!strcmp(keyFormat, "DER"))
        LoadPublicKey(publicFile, publicKey);
    else if (!strcmp(keyFormat, "PEM"))
        LoadBase64PublicKey(publicFile, publicKey);
    else
    {
        cerr << "Invalid key format, only DER or PEM are accepted" << endl;
        exit(1);
    }

    RSAES_OAEP_SHA_Encryptor e(publicKey);
    string plainText;
    FileSource(plainTextFile, true, new StringSink(plainText));

    StringSource(plainText, true, new PK_EncryptorFilter(rng, e, new FileSink(cipherTextFile)));
    cout << "Encrypted successfully, ciphertext is saved to \"" << cipherTextFile << "\"" << endl;
}


// Decrypt DER
void Decrypt(const char* keyFormat, const char* privateFile, const char* plainTextFile, const char* cipherTextFile)
{
    RSA::PrivateKey privateKey;
    AutoSeededRandomPool rng;

    if (!strcmp(keyFormat, "DER"))
        LoadPrivateKey(privateFile, privateKey);
    else if (!strcmp(keyFormat, "PEM"))
        LoadBase64PrivateKey(privateFile, privateKey);
    else
    {
        cerr << "Invalid key format, only DER or PEM are accepted" << endl;
        exit(1);
    }

    RSAES_OAEP_SHA_Decryptor d(privateKey);
    string cipherText;
    FileSource(cipherTextFile, true, new StringSink(cipherText));

    StringSource(cipherText, true, new PK_DecryptorFilter(rng, d, new FileSink(plainTextFile)));
    cout << "Decrypted successfully, plaintext is saved to \"" << plainTextFile << "\"" << endl;
}

void Usage()
{
    cout << "Usage: RSA_CLI <OPTION>" << endl;
    cout << "Options:" << endl;
    cout << "\tkeygen <keyFormat> <keySize> <privateFile> <publicFile>" << endl;
    cout << "\tencrypt <keyFormat> <publicFile> <plainTextFile> <cipherTextFile>" << endl;
    cout << "\tdecrypt <keyFormat> <privateFile> <recoveredTextFile> <cipherTextFile>" << endl;
}

int main(int argc, char* argv[])
{
    #ifdef __linux__
    std::locale::global(std::locale("C.utf8"));
    #endif
    
    #ifdef _WIN32
    // Set console code page to UTF-8 on Windows C.utf8, CP_UTF8
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    #endif

    std::ios_base::sync_with_stdio(false);

    if (argc != 6)
    {
        Usage();
        exit(1);
    }

    string choice = argv[1];
    if (choice == "keygen")
    {
        KeyGen(argv[2], stoi(argv[3]), argv[4], argv[5]);
    } else if (choice == "encrypt")
    {
        Encrypt(argv[2], argv[3], argv[4], argv[5]);
    } else if (choice == "decrypt")
    {
        Decrypt(argv[2], argv[3], argv[4], argv[5]);
    } else
    {
        Usage();
        exit(1);
    }

    return 0;
}


void SavePrivateKey(const string& filename, const PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void SavePublicKey(const string& filename, const PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void Save(const string& filename, const BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_sink.html
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}

void SaveBase64PrivateKey(const string& filename, const PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	SaveBase64(filename, queue);
}

void SaveBase64PublicKey(const string& filename, const PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	SaveBase64(filename, queue);
}

void SaveBase64(const string& filename, const BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_base64_encoder.html
	Base64Encoder encoder;

	bt.CopyTo(encoder);
	encoder.MessageEnd();

	Save(filename, encoder);
}

void LoadPrivateKey(const string& filename, PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);	
}

void LoadPublicKey(const string& filename, PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);	
}

void Load(const string& filename, BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_source.html
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}


void LoadBase64(const string& filename, BufferedTransformation& bt)
{
    Base64Decoder decoder;
    Load(filename,decoder);
 
    decoder.CopyTo(bt);
    bt.MessageEnd();
}
 
void LoadBase64PrivateKey(const string& filename, PrivateKey& key)
{
    ByteQueue queue;
 
    LoadBase64(filename, queue);
    key.Load(queue);    
}
 
void LoadBase64PublicKey(const string& filename, PublicKey& key)
{
    ByteQueue queue;
 
    LoadBase64(filename, queue);
    key.Load(queue);    
}
