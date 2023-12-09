using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {

        Console.Write("Enter the mode: (1 - file encryption, 2 - signature verification): ");
        var mode = Console.ReadLine();
        if (mode == "1")
        {
            Console.Write("Enter the encryption key: ");
            var encryptionKey = Console.ReadLine();

            Console.Write("Enter the name of the file to be encrypted: ");
            var inputFile = Console.ReadLine();

            Console.Write("Enter the name of the file to save the encrypted information: ");
            var encryptedFile = Console.ReadLine();

            EncryptFile(inputFile, encryptedFile, encryptionKey);

            DecryptFile(encryptedFile, "decrypted_" + inputFile, encryptionKey);
            Console.ReadLine();
        }
        else if (mode == "2")
        {
            Console.Write("Enter the name of the file to be encrypted: ");
            var inputFile = Console.ReadLine();

            Console.Write("Enter the name of the file to save the encrypted information: ");
            var encryptedFile = Console.ReadLine();

            Console.Write("Enter the digital signature key (8 characters): ");
            var signatureKey = Console.ReadLine();
            var digitalSignature = GenerateDigitalSignature(inputFile, signatureKey);

            var isSignatureValid = VerifyDigitalSignature(inputFile, digitalSignature, signatureKey);
            Console.WriteLine("Digital Signature Verification: " + isSignatureValid);
            Console.ReadLine();
        }
    }

    static void EncryptFile(string inputFile, string outputFile, string encryptionKey)
    {
        using DESCryptoServiceProvider des = new DESCryptoServiceProvider();
        des.Key = Encoding.UTF8.GetBytes(encryptionKey);
        byte[] iv = Encoding.UTF8.GetBytes("12345678");
        des.IV = iv;

        using (var fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
        using (var fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
        using (var encryptor = des.CreateEncryptor())
        using (var cryptoStream = new CryptoStream(fsOutput, encryptor, CryptoStreamMode.Write))
        {
            int bytesRead;
            var buffer = new byte[1024];
            while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
            {
                cryptoStream.Write(buffer, 0, bytesRead);
            }
        }

        Console.WriteLine("File encrypted successfully.");
    }

    static void DecryptFile(string inputFile, string outputFile, string encryptionKey)
    {
        using DESCryptoServiceProvider des = new DESCryptoServiceProvider();
        des.Key = Encoding.UTF8.GetBytes(encryptionKey);
        des.IV = Encoding.UTF8.GetBytes("12345678");

        using (var fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
        using (var fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
        using (var decryptor = des.CreateDecryptor())
        using (var cryptoStream = new CryptoStream(fsOutput, decryptor, CryptoStreamMode.Write))
        {
            int bytesRead;
            var buffer = new byte[1024];
            while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
            {
                cryptoStream.Write(buffer, 0, bytesRead);
            }
        }

        Console.WriteLine("File decrypted successfully.");
    }

    static string GenerateDigitalSignature(string inputFile, string signatureKey)
    {
        using DESCryptoServiceProvider des = new DESCryptoServiceProvider();
        des.Key = Encoding.UTF8.GetBytes(signatureKey);
        des.IV = Encoding.UTF8.GetBytes("12345678");

        using var fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read);
        using var encryptor = des.CreateEncryptor();

        using var ms = new MemoryStream();
        using var cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);

        int bytesRead;
        var buffer = new byte[des.BlockSize / 8]; // BlockSize в бітах, отримуємо довжину блоку в байтах
        byte[] previousCipherBlock = des.IV; // Початковий блок для CBC - IV

        while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
        {
            for (int i = 0; i < buffer.Length; i++)
            {
                buffer[i] ^= previousCipherBlock[i]; // Виконуємо операцію XOR з попереднім шифртекстом (CBC)
            }

            cryptoStream.Write(buffer, 0, buffer.Length);
            previousCipherBlock = buffer.ToArray(); // Попередній шифртекст для наступного блоку
        }

        cryptoStream.FlushFinalBlock();
        return Convert.ToBase64String(ms.ToArray());
    }

    static bool VerifyDigitalSignature(string inputFile, string digitalSignature, string signatureKey)
    {
        using DESCryptoServiceProvider des = new DESCryptoServiceProvider();
        des.Key = Encoding.UTF8.GetBytes(signatureKey);
        des.IV = Encoding.UTF8.GetBytes("12345678");

        using var decryptor = des.CreateDecryptor();
        using var ms = new MemoryStream(Convert.FromBase64String(digitalSignature));
        using var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);

        using var decryptedMs = new MemoryStream();
        byte[] buffer = new byte[des.BlockSize / 8]; // Block size in bytes

        byte[] previousCipherBlock = des.IV; // Initialize with IV for CBC mode

        int bytesRead;
        while ((bytesRead = cryptoStream.Read(buffer, 0, buffer.Length)) > 0)
        {
            byte[] decryptedBlock = new byte[bytesRead];
            Buffer.BlockCopy(buffer, 0, decryptedBlock, 0, bytesRead);

            for (int i = 0; i < bytesRead; i++)
            {
                byte temp = buffer[i];
                buffer[i] ^= previousCipherBlock[i]; // Reverse CBC chaining
                previousCipherBlock[i] = temp;
            }

            decryptedMs.Write(buffer, 0, bytesRead);
        }

        decryptedMs.Position = 0;
        byte[] decryptedBytes = decryptedMs.ToArray();
        byte[] originalBytes = File.ReadAllBytes(inputFile);

        // Pad the decrypted bytes to match the length of the original file
        Array.Resize(ref decryptedBytes, originalBytes.Length);

        return decryptedBytes.SequenceEqual(originalBytes);
    }
}
