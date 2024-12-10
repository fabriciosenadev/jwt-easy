using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JwtService;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using Moq;

namespace JwtManagerTests;

public class JwtManagerUnitTests
{
    [Fact]
    public void StartGeneration_ValidSecret_StoresSecret()
    {
        // Arrange
        string secret = "my_secret_key";
        IJwtManager jwtManager = new JwtManager(secret);

        // Act
        jwtManager.StartGeneration(secret);

        // Assert
        // Here, we need a way to access the _secret field from the implementation
        // of the IJwtManager interface. Since we don't have direct access, we can
        // use reflection to access the private field.
        // WARNING: Using reflection to access private fields is considered
        // bad practice and should be used with caution.
        var secretField = jwtManager.GetType().GetField("_secret", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.Equal(secret, secretField.GetValue(jwtManager));
    }

    [Fact]
    public void StartGeneration_NullSecret_ThrowsArgumentNullException()
    {
        // Arrange
        string secret = null;
        IJwtManager jwtManager = new JwtManager("initial_secret");

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => jwtManager.StartGeneration(secret));
    }

    [Fact]
    public void WithClaims_ValidClaims_StoresClaims()
    {
        // Arrange
        IJwtManager jwtManager = new JwtManager("secret");
        List<KeyValuePair<string, string>> claims = new List<KeyValuePair<string, string>>
    {
        new KeyValuePair<string, string>("department", "marketing"),
        new KeyValuePair<string, string>("location", "NewYork")
    };

        // Act
        jwtManager.WithClaims(claims);

        // Assert
        var claimsField = jwtManager.GetType().GetField("_claims", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.Equal(claims, claimsField.GetValue(jwtManager));
    }

    [Fact]
    public void WithClaims_EmptyClaims_ThrowsArgumentException()
    {
        // Arrange
        IJwtManager jwtManager = new JwtManager("secret");
        List<KeyValuePair<string, string>> claims = new List<KeyValuePair<string, string>>();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => jwtManager.WithClaims(claims));
    }

    [Fact]
    public void WithClaims_NullClaims_DoesNotStoreClaims()
    {
        // Arrange
        IJwtManager jwtManager = new JwtManager("secret");
        List<KeyValuePair<string, string>> claims = null;

        // Act
        jwtManager.WithClaims(claims);

        // Assert
        var claimsField = jwtManager.GetType().GetField("_claims", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.Empty((List<KeyValuePair<string, string>>)claimsField.GetValue(jwtManager));
    }

    [Fact]
    public void WithClaims_InvalidClaimName_ThrowsArgumentException()
    {
        // Arrange
        IJwtManager jwtManager = new JwtManager("secret");
        List<KeyValuePair<string, string>> claims = new List<KeyValuePair<string, string>>
        {
            new KeyValuePair<string, string>("123department", "marketing")
        };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => jwtManager.WithClaims(claims));
    }

    [Fact]
    public void WithClaims_ClaimNameStartsWithNumber_ThrowsArgumentException()
    {
        // Arrange
        IJwtManager jwtManager = new JwtManager("secret");
        List<KeyValuePair<string, string>> claims = new List<KeyValuePair<string, string>>
        {
            new KeyValuePair<string, string>("1department", "marketing") // Invalid claim name
        };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => jwtManager.WithClaims(claims));
    }

    [Fact]
    public void WithClaims_ClaimNameContainsSpecialCharacters_ThrowsArgumentException()
    {
        // Arrange
        IJwtManager jwtManager = new JwtManager("secret");
        List<KeyValuePair<string, string>> claims = new List<KeyValuePair<string, string>>
        {
            new KeyValuePair<string, string>("department!", "marketing") // Invalid claim name
        };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => jwtManager.WithClaims(claims));
    }
    [Fact]
    public void WithExpiration_ValidExpiration_StoresExpiration()
    {
        // Arrange
        IJwtManager jwtManager = new JwtManager("secret");
        ExpirationType expirationType = ExpirationType.Hours;
        int expirationValue = 1;

        // Act
        jwtManager.WithExpiration(expirationType, expirationValue);

        // Assert
        var expirationTypeField = jwtManager.GetType().GetField("_expirationType", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        var expirationValueField = jwtManager.GetType().GetField("_expirationValue", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.Equal(expirationType, expirationTypeField.GetValue(jwtManager));
        Assert.Equal(expirationValue, expirationValueField.GetValue(jwtManager));
    }

    [Fact]
    public void WithExpiration_InvalidExpiration_ThrowsArgumentException()
    {
        // Arrange
        IJwtManager jwtManager = new JwtManager("secret");
        ExpirationType expirationType = ExpirationType.Days;
        int expirationValue = 0;

        // Act & Assert
        Assert.Throws<ArgumentException>(() => jwtManager.WithExpiration(expirationType, expirationValue));
    }

    [Fact]
    public void WithIssuer_ValidIssuer_StoresIssuer()
    {
        // Arrange
        IJwtManager jwtManager = new JwtManager("secret");
        string issuer = "my-app";

        // Act
        jwtManager.WithIssuer(issuer);

        // Assert
        var issuerField = jwtManager.GetType().GetField("_issuer", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.Equal(issuer, issuerField.GetValue(jwtManager));
    }

    [Fact]
    public void WithAudience_ValidAudience_StoresAudience()
    {
        // Arrange
        IJwtManager jwtManager = new JwtManager("secret");
        string audience = "my-client";

        // Act
        jwtManager.WithAudience(audience);

        // Assert
        var audienceField = jwtManager.GetType().GetField("_audience", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.Equal(audience, audienceField.GetValue(jwtManager));
    }

    [Fact]
    public void WithSigningAlgorithm_ValidAlgorithm_StoresAlgorithm()
    {
        // Arrange
        IJwtManager jwtManager = new JwtManager("secret");
        string algorithm = "HS256";

        // Act
        jwtManager.WithSigningAlgorithm(algorithm);

        // Assert
        var algorithmField = jwtManager.GetType().GetField("_algorithm", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.Equal(algorithm, algorithmField.GetValue(jwtManager));
    }

    [Fact]
    public void WithSigningAlgorithm_InvalidAlgorithm_ThrowsArgumentException()
    {
        // Arrange
        IJwtManager jwtManager = new JwtManager("secret");
        string algorithm = "";

        // Act & Assert
        Assert.Throws<ArgumentException>(() => jwtManager.WithSigningAlgorithm(algorithm));
    }

    [Fact]
    public void WithHeader_ValidHeader_StoresHeader()
    {
        // Arrange
        IJwtManager jwtManager = new JwtManager("secret");
        Dictionary<string, object> header = new Dictionary<string, object>
        {
            { "alg", "HS256" },
            { "typ", "JWT" }
        };

        // Act
        jwtManager.WithHeader(header);

        // Assert
        var headerField = jwtManager.GetType().GetField("_header", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.Equal(header, headerField.GetValue(jwtManager));
    }

    [Fact]
    public void WithHeader_NullHeader_DoesNotStoreHeader()
    {
        // Arrange
        IJwtManager jwtManager = new JwtManager("secret");
        Dictionary<string, object> header = null;

        // Act
        jwtManager.WithHeader(header);

        // Assert
        var headerField = jwtManager.GetType().GetField("_header", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.Empty((Dictionary<string, object>)headerField.GetValue(jwtManager));
    }

    [Fact]
    public void GenerateToken_WithValidData_ReturnsValidToken()
    {
        // Arrange
        var secret = "my_super_secret_key_12345_my_super_secret_key"; // Simulates a secret key
        var algorithm = SecurityAlgorithms.HmacSha256; // Signing algorithm
        var claims = new List<KeyValuePair<string, string>>
    {
        new KeyValuePair<string, string>("department", "marketing"),
        new KeyValuePair<string, string>("location", "NewYork")
    };
        var issuer = "my-app";
        var audience = "my-client";
        var expiration = DateTime.UtcNow.AddHours(1); // Token valid for 1 hour
        var header = new Dictionary<string, object>
    {
        { "alg", "HS256" },
        { "typ", "JWT" }
    };

        var jwtManager = new JwtManager(JwtTokenMocker.Secret)
            .WithClaims(claims)
            .WithIssuer(issuer)
            .WithAudience(audience)
            .WithExpiration(ExpirationType.Hours, 1)
            .WithHeader(header);

        // Act
        var token = jwtManager.GenerateToken();

        // Assert
        Assert.NotNull(token); // Ensures that the token was generated
        var handler = new JwtSecurityTokenHandler();
        Assert.True(handler.CanReadToken(token)); // Ensures that the token can be read

        var decodedToken = handler.ReadJwtToken(token);

        // Verifies the claims
        Assert.Equal("marketing", decodedToken.Claims.FirstOrDefault(c => c.Type == "department")?.Value);
        Assert.Equal("NewYork", decodedToken.Claims.FirstOrDefault(c => c.Type == "location")?.Value);

        // Verifies the issuer, audience, and expiration
        Assert.Equal(issuer, decodedToken.Issuer);
        Assert.Equal(audience, decodedToken.Audiences.FirstOrDefault());
        Assert.True(decodedToken.ValidTo > DateTime.UtcNow); // Ensures that it has not expired yet

        // Verifies the header
        Assert.Equal("HS256", decodedToken.Header["alg"]);
        Assert.Equal("JWT", decodedToken.Header["typ"]);
    }

    private string GenerateValidToken(Dictionary<string, string> claims)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(JwtTokenMocker.Secret);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims.Select(c => new Claim(c.Key, c.Value))),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    [Fact]
    public void GetClaimsFromToken_WithValidToken_ReturnsClaims()
    {
        // Arrange
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);
        var claims = new Dictionary<string, string>
        {
            { "department", "IT" },
            { "location", "NY" }
        };
        var token = GenerateValidToken(claims);

        // Act
        var result = jwtManager.GetClaimsFromToken(token);

        // Assert
        Assert.NotNull(result);
        Assert.Contains(result, c => c.Type == "department" && c.Value == "IT");
        Assert.Contains(result, c => c.Type == "location" && c.Value == "NY");
    }

    [Fact]
    public void GetClaimsFromToken_WithNullToken_ThrowsArgumentException()
    {
        // Arrange
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => jwtManager.GetClaimsFromToken(null));
        Assert.Equal("The token cannot be null or empty. (Parameter 'token')", exception.Message);
    }

    [Fact]
    public void GetClaimsFromToken_WithEmptyToken_ThrowsArgumentException()
    {
        // Arrange
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => jwtManager.GetClaimsFromToken(string.Empty));
        Assert.Equal("The token cannot be null or empty. (Parameter 'token')", exception.Message);
    }

    [Fact]
    public void GetClaimsFromToken_WithInvalidToken_ThrowsException()
    {
        // Arrange
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);
        var invalidToken = "invalid_token";

        // Act & Assert
        var exception = Assert.Throws<Exception>(() => jwtManager.GetClaimsFromToken(invalidToken));
        Assert.Equal("Invalid token.", exception.Message);
    }

    [Fact]
    public void IsTokenExpired_WithExpiredToken_ReturnsTrue()
    {
        // Arrange
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);
        var expiredToken = JwtTokenMocker.GenerateExpiredToken(DateTime.UtcNow.AddMinutes(-5)); // Token expired 5 minutes ago

        // Act
        var result = jwtManager.IsTokenExpired(expiredToken);

        // Assert
        Assert.True(result); // Token is expired
    }

    [Fact]
    public void IsTokenExpired_WithValidToken_ReturnsFalse()
    {
        // Arrange
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);
        var validToken = JwtTokenMocker.GenerateExpiredToken(DateTime.UtcNow.AddMinutes(5)); // Token valid for 5 more minutes

        // Act
        var result = jwtManager.IsTokenExpired(validToken);

        // Assert
        Assert.False(result); // Token is not expired
    }

    [Fact]
    public void IsTokenExpired_WithNullToken_ThrowsArgumentException()
    {
        // Arrange
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => jwtManager.IsTokenExpired(null));
        Assert.Equal("The token cannot be null or empty. (Parameter 'token')", exception.Message);
    }

    [Fact]
    public void IsTokenExpired_WithEmptyToken_ThrowsArgumentException()
    {
        // Arrange
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => jwtManager.IsTokenExpired(string.Empty));
        Assert.Equal("The token cannot be null or empty. (Parameter 'token')", exception.Message);
    }

    [Fact]
    public void IsTokenExpired_WithInvalidToken_ThrowsException()
    {
        // Arrange
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);
        var invalidToken = "invalid_token";

        // Act & Assert
        var exception = Assert.Throws<Exception>(() => jwtManager.IsTokenExpired(invalidToken));
        Assert.Equal("Invalid token.", exception.Message);
    }

    [Fact]
    public void GetIssuerFromToken_WithValidToken_ReturnsIssuer()
    {
        // Arrange
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);
        var issuer = "test-issuer";
        var token = JwtTokenMocker.GenerateTokenWithIssuer(issuer);

        // Act
        var result = jwtManager.GetIssuerFromToken(token);

        // Assert
        Assert.Equal(issuer, result);
    }

    [Fact]
    public void GetIssuerFromToken_WithTokenWithoutIssuer_ReturnsNull()
    {
        // Arrange
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);
        var token = JwtTokenMocker.GenerateTokenWithIssuer(null); // Token without emissor

        // Act
        var result = jwtManager.GetIssuerFromToken(token);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void GetIssuerFromToken_WithNullToken_ThrowsArgumentException()
    {
        // Arrange
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => jwtManager.GetIssuerFromToken(null));
        Assert.Equal("The token cannot be null or empty. (Parameter 'token')", exception.Message);
    }

    [Fact]
    public void GetIssuerFromToken_WithEmptyToken_ThrowsArgumentException()
    {
        // Arrange
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => jwtManager.GetIssuerFromToken(string.Empty));
        Assert.Equal("The token cannot be null or empty. (Parameter 'token')", exception.Message);
    }

    [Fact]
    public void GetIssuerFromToken_WithInvalidToken_ThrowsException()
    {
        // Arrange
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);
        var invalidToken = "invalid_token";

        // Act & Assert
        var exception = Assert.Throws<Exception>(() => jwtManager.GetIssuerFromToken(invalidToken));
        Assert.Equal("Invalid token.", exception.Message);
    }

    [Fact]
    public void GetAudienceFromToken_ValidTokenWithAudience_ReturnsAudience()
    {
        // Arrange
        var audience = "test-audience";
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);
        var token = JwtTokenMocker.GenerateTokenWithAudience(audience);

        // Act
        var result = jwtManager.GetAudienceFromToken(token);

        // Assert
        Assert.Equal(audience, result);
    }

    [Fact]
    public void GetAudienceFromToken_TokenWithoutAudience_ReturnsNull()
    {
        // Arrange
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);
        var token = JwtTokenMocker.GenerateTokenWithoutAudience();

        // Act
        var result = jwtManager.GetAudienceFromToken(token);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void GetAudienceFromToken_InvalidToken_ThrowsException()
    {
        // Arrange
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);
        var invalidToken = "InvalidTokenString";

        // Act & Assert
        var exception = Assert.Throws<Exception>(() => jwtManager.GetAudienceFromToken(invalidToken));
        Assert.Contains("Invalid token.", exception.Message);
    }

    [Fact]
    public void GetAudienceFromToken_NullToken_ThrowsArgumentException()
    {
        // Arrange
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => jwtManager.GetAudienceFromToken(null));
        Assert.Contains("The token cannot be null or empty.", exception.Message);
    }

    [Fact]
    public void GetAudienceFromToken_EmptyToken_ThrowsArgumentException()
    {
        // Arrange
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => jwtManager.GetAudienceFromToken(string.Empty));
        Assert.Contains("The token cannot be null or empty.", exception.Message);
    }

    [Fact]
    public void GetHeadersFromToken_ValidToken_ReturnsHeaders()
    {
        // Arrange
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);
        var headers = new Dictionary<string, object>
        {
            { "kid", "test-key-id" },
            { "alg", "HS256" }
        };
        var token = JwtTokenMocker.GenerateTokenWithHeader(headers);

        // Act
        var result = jwtManager.GetHeadersFromToken(token);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("test-key-id", result["kid"]);
        Assert.Equal("HS256", result["alg"]);
    }

    [Fact]
    public void GetHeadersFromToken_InvalidToken_ThrowsException()
    {
        // Arrange
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);
        var invalidToken = "invalid.token.value";

        // Act & Assert
        var exception = Assert.Throws<Exception>(() => jwtManager.GetHeadersFromToken(invalidToken));
        Assert.Contains("Invalid token", exception.Message);
    }

    [Fact]
    public void GetHeadersFromToken_NullOrEmptyToken_ThrowsArgumentException()
    {
        // Arrange
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);

        // Act & Assert
        Assert.Throws<ArgumentException>(() => jwtManager.GetHeadersFromToken(null));
        Assert.Throws<ArgumentException>(() => jwtManager.GetHeadersFromToken(string.Empty));
    }

    [Fact]
    public void GetHeadersFromToken_TokenWithoutJwtSecurityToken_ThrowsException()
    {
        // Arrange
        var jwtManager = new JwtManager(JwtTokenMocker.Secret);
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = "non-jwt-token";

        // Act & Assert
        var exception = Assert.Throws<Exception>(() => jwtManager.GetHeadersFromToken(token));
        Assert.Contains("Invalid token.", exception.Message); // Verify correct message
    }
}
