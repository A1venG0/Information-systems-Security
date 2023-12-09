#include <iostream>
#include <random>
#include <cmath>
#include <fstream>
#include <vector>

// binary exponentiation
int power(int x, unsigned int y, int p)
{
    int res = 1;
    x = x % p;
    while (y > 0)
    {
        if (y & 1)
            res = (res * x) % p;
 
        y = y >> 1;
        x = (x * x) % p;
    }
    return res;
}
 
bool miillerTest(int d, int n)
{
    // Pick a random number in [2..n-2]
    int a = 2 + rand() % (n - 4);
 
    // Compute a^d % n
    int x = power(a, d, n);
 
    if (x == 1 || x == n-1)
       return true;
 
    // Keep squaring x while one of the following doesn't
    // happen
    // (i)   d does not reach n-1
    // (ii)  (x^2) % n is not 1
    // (iii) (x^2) % n is not n-1
    while (d != n-1)
    {
        x = (x * x) % n;
        d *= 2;
 
        if (x == 1)
            return false;
        if (x == n-1)
            return true;
    }
 
    // Return composite
    return false;
}
 

bool isPrime(int n, int k)
{
    // Corner cases
    if (n <= 1 || n == 4)  return false;
    if (n <= 3) return true;
 
    // Find r such that n = 2^d * r + 1 for some r >= 1
    int d = n - 1;
    while (d % 2 == 0)
        d /= 2;
 
    for (int i = 0; i < k; i++)
         if (!miillerTest(d, n))
              return false;
 
    return true;
}

long long int generatePrime(int bitLength) {
    long long int num;
    do {
        num = rand() % (1 << (bitLength - 1));
        num |= (1LL << (bitLength - 1)); // Set highest bit to ensure correct bit length
    } while (!isPrime(num, 10));

    return num;
}

long long int gcd(long long int a, long long int b) {
    if (b == 0) return a;
    return gcd(b, a % b);
}

// x1 * e = 1 (mod phi)
long long int modInverse(long long int a, long long int m) {
    long long int m0 = m, t, q;
    long long int x0 = 0, x1 = 1;

    if (m == 1) return 0; // coprime

    while (a > 1) {
        q = a / m;
        t = m;

        m = a % m, a = t;
        t = x0;

        x0 = x1 - q * x0; // Bézout coefficients
        x1 = t;
    }

    if (x1 < 0) x1 += m0;

    return x1;
}

std::vector<unsigned long long> encryptRSA(const std::vector<unsigned long long>& message, unsigned long long e, unsigned long long n) {
    std::vector<unsigned long long> encrypted;

    for (auto m : message) {
        unsigned long long encryptedPart = 1;
        for (unsigned long long i = 0; i < e; ++i) {
            encryptedPart = (encryptedPart * m) % n;
        }
        encrypted.push_back(encryptedPart);
    }

    return encrypted;
}

// Function to perform RSA decryption
std::vector<unsigned long long> decryptRSA(const std::vector<unsigned long long>& encrypted, unsigned long long d, unsigned long long n) {
    std::vector<unsigned long long> decrypted;

    for (auto c : encrypted) {
        unsigned long long decryptedPart = 1;
        for (unsigned long long i = 0; i < d; ++i) {
            decryptedPart = (decryptedPart * c) % n;
        }
        decrypted.push_back(decryptedPart);
    }

    return decrypted;
}

int main() {
    int keyLength;
    std::cout << "Enther the desired key length: ";
    std::cin >> keyLength;

    // Generate two random prime numbers
    long long int p = generatePrime(keyLength / 2);
    long long int q = generatePrime(keyLength / 2);

    // Calculate modulus n and Euler's totient function phi(n)
    long long int n = p * q;
    long long int phi = (p - 1) * (q - 1);

    long long int e = 65537;

    // Calculate private key
    long long int d = modInverse(e, phi);

    std::ifstream inputFile("input_file.txt", std::ios::binary);
    if (!inputFile) {
        std::cerr << "Error: Unable to open input file." << std::endl;
        return 1;
    }

    // Read the content of the input file into a vector
    std::vector<unsigned long long> message;
    char ch;
    while (inputFile.get(ch)) {
        message.push_back(static_cast<unsigned long long>(ch));
    }

    // Encrypt the file content using the public key (e, n)
    std::vector<unsigned long long> encrypted = encryptRSA(message, e, n);

    std::ofstream outputEncryptedFile("encrypted_file.txt", std::ios::binary);
    if (!outputEncryptedFile) {
        std::cerr << "Error: Unable to open encrypted output file." << std::endl;
        return 1;
    }

    for (auto num : encrypted) {
        outputEncryptedFile.put(num);
    }

    // Perform decryption using the private key (d, n)
    std::vector<unsigned long long> decrypted = decryptRSA(encrypted, d, n);

    // Write the decrypted content to an output file
    std::ofstream outputFile("decrypted_file.txt", std::ios::binary);
    if (!outputFile) {
        std::cerr << "Error: Unable to open output file." << std::endl;
        return 1;
    }

    for (auto num : decrypted) {
        outputFile.put(static_cast<char>(num));
    }

    std::cout << "Encryption and decryption completed successfully." << std::endl;

    return 0;
}