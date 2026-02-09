using System.Text.Json;

namespace AceJobAgency.Services
{
    public interface IReCaptchaService
    {
        Task<bool> VerifyAsync(string token);
        Task<double> GetScoreAsync(string token);
    }

    public class ReCaptchaService : IReCaptchaService
    {
        private readonly HttpClient _httpClient;
        private readonly string _secretKey;
        private readonly ILogger<ReCaptchaService> _logger;

        public ReCaptchaService(IConfiguration configuration, HttpClient httpClient, ILogger<ReCaptchaService> logger)
        {
            _httpClient = httpClient;
            _secretKey = configuration["ReCaptcha:SecretKey"] ?? throw new InvalidOperationException("ReCaptcha SecretKey not configured");
            _logger = logger;
        }

        public async Task<bool> VerifyAsync(string token)
        {
            var score = await GetScoreAsync(token);
            return score >= 0.5; // reCAPTCHA v3 uses scores from 0.0 to 1.0
        }

        public async Task<double> GetScoreAsync(string token)
        {
            if (string.IsNullOrEmpty(token))
                return 0;

            try
            {
                var response = await _httpClient.PostAsync(
                    $"https://www.google.com/recaptcha/api/siteverify?secret={_secretKey}&response={token}",
                    null);

                var jsonString = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<ReCaptchaResponse>(jsonString);

                if (result?.success == true)
                {
                    return result.score;
                }

                _logger.LogWarning("ReCaptcha verification failed: {Errors}", result?.error_codes);
                return 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying reCAPTCHA");
                return 0;
            }
        }

        private class ReCaptchaResponse
        {
            public bool success { get; set; }
            public double score { get; set; }
            public string? action { get; set; }
            public string? challenge_ts { get; set; }
            public string? hostname { get; set; }
            public string[]? error_codes { get; set; }
        }
    }
}
