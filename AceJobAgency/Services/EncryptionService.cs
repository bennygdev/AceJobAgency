using System.Security.Cryptography;
using System.Text;

namespace AceJobAgency.Services
{
    public interface IEncryptionService
    {
        string Encrypt(string plainText);
        string Decrypt(string cipherText);
    }

    public class EncryptionService : IEncryptionService
    {
        private readonly byte[] _key;

        public EncryptionService(IConfiguration configuration)
        {
            // Get encryption key from configuration
            var keyString = configuration["Encryption:Key"] ?? throw new InvalidOperationException("Encryption key not configured");
            _key = Convert.FromBase64String(keyString);
        }

        public string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
                return string.Empty;

            using var aes = Aes.Create();
            aes.Key = _key;
            aes.GenerateIV(); // Generate a random IV for each encryption
            var iv = aes.IV;

            var encryptor = aes.CreateEncryptor(aes.Key, iv);

            using var msEncrypt = new MemoryStream();
            // Write the IV at the beginning of the stream
            msEncrypt.Write(iv, 0, iv.Length);

            using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            using (var swEncrypt = new StreamWriter(csEncrypt))
            {
                swEncrypt.Write(plainText);
            }

            return Convert.ToBase64String(msEncrypt.ToArray());
        }

        public string Decrypt(string cipherText)
        {
            if (string.IsNullOrEmpty(cipherText))
                return string.Empty;

            try
            {
                var fullCipher = Convert.FromBase64String(cipherText);

                using var aes = Aes.Create();
                aes.Key = _key;

                // Extract the IV from the beginning of the ciphertext
                var iv = new byte[aes.BlockSize / 8];
                if (fullCipher.Length < iv.Length)
                    return "[Decryption Error]"; // Ciphertext too short

                Array.Copy(fullCipher, 0, iv, 0, iv.Length);
                aes.IV = iv;

                var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using var msDecrypt = new MemoryStream(fullCipher, iv.Length, fullCipher.Length - iv.Length);
                using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                using var srDecrypt = new StreamReader(csDecrypt);

                return srDecrypt.ReadToEnd();
            }
            catch
            {
                return "[Decryption Error]";
            }
        }

        // Static method to generate new key (IV generation is now handled per encryption)
        public static (string Key, string IV) GenerateNewKeys()
        {
            using var aes = Aes.Create();
            aes.GenerateKey();
            // IV is not needed in config anymore, but keeping signature compatible or just returning dummy
            return (Convert.ToBase64String(aes.Key), "Auto-Generated-Per-Encryption");
        }
    }
}
