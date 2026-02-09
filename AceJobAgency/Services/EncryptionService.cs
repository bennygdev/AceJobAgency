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
        private readonly byte[] _iv;

        public EncryptionService(IConfiguration configuration)
        {
            // Get encryption key from configuration
            var keyString = configuration["Encryption:Key"] ?? throw new InvalidOperationException("Encryption key not configured");
            var ivString = configuration["Encryption:IV"] ?? throw new InvalidOperationException("Encryption IV not configured");

            _key = Convert.FromBase64String(keyString);
            _iv = Convert.FromBase64String(ivString);
        }

        public string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
                return string.Empty;

            using var aes = Aes.Create();
            aes.Key = _key;
            aes.IV = _iv;

            var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using var msEncrypt = new MemoryStream();
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
                var cipherBytes = Convert.FromBase64String(cipherText);

                using var aes = Aes.Create();
                aes.Key = _key;
                aes.IV = _iv;

                var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using var msDecrypt = new MemoryStream(cipherBytes);
                using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                using var srDecrypt = new StreamReader(csDecrypt);

                return srDecrypt.ReadToEnd();
            }
            catch
            {
                return "[Decryption Error]";
            }
        }

        // Static method to generate new keys for configuration
        public static (string Key, string IV) GenerateNewKeys()
        {
            using var aes = Aes.Create();
            aes.GenerateKey();
            aes.GenerateIV();
            return (Convert.ToBase64String(aes.Key), Convert.ToBase64String(aes.IV));
        }
    }
}
