using System;
using System.Text;
using System.Collections.Generic;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace JwtManager;

/// <summary>
/// JWT token manager.
/// </summary>
public class JwtManager : IJwtManager
{
    private string _secret;
    private List<KeyValuePair<string, string>> _claims = new List<KeyValuePair<string, string>>();
    private ExpirationType _expirationType = ExpirationType.Days;
    private int _expirationValue = 7;
    private string _issuer;
    private string _audience;
    private string _algorithm = SecurityAlgorithms.HmacSha256Signature;
    private Dictionary<string, object> _header = new Dictionary<string, object>();

    /// <summary>
    /// Constructor for the `JwtManager` class.
    /// </summary>
    /// <param name="secret">The secret key to sign the token.</param>
    public JwtManager(string secret)
    {
        if (string.IsNullOrEmpty(secret))
        {
            throw new ArgumentNullException(nameof(secret), "The secret key is required.");
        }
        _secret = secret;
    }

    /// <summary>
    /// Starts the generation of a new JWT token.
    /// </summary>
    /// <param name="secret">The secret key to sign the token.</param>
    /// <returns>The current instance of `IJwtManager` for method chaining.</returns>
    public IJwtManager StartGeneration(string secret)
    {
        if (string.IsNullOrEmpty(secret))
        {
            throw new ArgumentNullException(nameof(secret), "The secret key is required.");
        }

        _secret = secret; // Stores the secret key in the current instance
        return this; // Returns the current instance
    }

    /// <summary>
    /// Adds claims to the JWT token.
    /// </summary>
    /// <param name="claims">A list of claims to be added to the token.</param>
    /// <returns>The current instance of `IJwtManager` for method chaining.</returns>
    public IJwtManager WithClaims(List<KeyValuePair<string, string>> claims)
    {
        if (claims != null)
        {
            // Checks if the claims list is not null and not empty
            if (claims.Count == 0)
            {
                throw new ArgumentException("The claims list cannot be empty.", nameof(claims));
            }

            // Checks if all claims have valid key and value
            foreach (var claim in claims)
            {
                if (string.IsNullOrEmpty(claim.Key))
                {
                    throw new ArgumentException("The claim key cannot be null or empty.", nameof(claims));
                }
                if (string.IsNullOrEmpty(claim.Value))
                {
                    throw new ArgumentException("The claim value cannot be null or empty.", nameof(claims));
                }

                // Validates the claim name format
                if (!IsValidClaimName(claim.Key))
                {
                    throw new ArgumentException($"Invalid claim name: {claim.Key}. Claim names must start with a letter and can contain letters, numbers, underscores, and hyphens.", nameof(claims));
                }
            }

            _claims = claims;
        }

        return this;
    }

    /// <summary>
    /// Sets the expiration date of the JWT token.
    /// </summary>
    /// <param name="expirationType">The type of expiration (minutes, hours, days).</param>
    /// <param name="expirationValue">The expiration value. Default is 7 days.</param>
    /// <returns>The current instance of `IJwtManager` for method chaining.</returns>
    public IJwtManager WithExpiration(ExpirationType expirationType, int expirationValue)
    {
        if (expirationValue <= 0)
        {
            throw new ArgumentException("The expiration value must be greater than zero.", nameof(expirationValue));
        }

        _expirationType = expirationType;
        _expirationValue = expirationValue;
        return this;
    }

    /// <summary>
    /// Sets the issuer of the JWT token.
    /// </summary>
    /// <param name="issuer">The issuer of the token.</param>
    /// <returns>The current instance of `IJwtManager` for method chaining.</returns>
    public IJwtManager WithIssuer(string issuer)
    {
        _issuer = issuer;
        return this;
    }

    /// <summary>
    /// Sets the audience of the JWT token.
    /// </summary>
    /// <param name="audience">The audience of the token.</param>
    /// <returns>The current instance of `IJwtManager` for method chaining.</returns>
    public IJwtManager WithAudience(string audience)
    {
        _audience = audience;
        return this;
    }

    /// <summary>
    /// Sets the signing algorithm for the JWT token.
    /// </summary>
    /// <param name="algorithm">The signing algorithm. Default is HMAC SHA256.</param>
    /// <returns>The current instance of `IJwtManager` for method chaining.</returns>
    public IJwtManager WithSigningAlgorithm(string algorithm)
    {
        if (string.IsNullOrEmpty(algorithm))
        {
            throw new ArgumentException("The signing algorithm cannot be null or empty.", nameof(algorithm));
        }

        _algorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Adds additional information to the JWT token header.
    /// </summary>
    /// <param name="header">A dictionary of key-value pairs to be added to the header.</param>
    /// <returns>The current instance of `IJwtManager` for method chaining.</returns>
    public IJwtManager WithHeader(Dictionary<string, object> header)
    {
        if (header != null)
        {
            foreach (var item in header)
            {
                _header.Add(item.Key, item.Value);
            }
        }

        return this;
    }

    /// <summary>
    /// Generates the JWT token.
    /// </summary>
    /// <returns>The generated JWT token.</returns>
    public string GenerateToken()
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_secret);

        var tokenDescription = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(
                _claims.Select(c => new Claim(c.Key, c.Value)).ToArray()
            ),
            Expires = GetExpirationDate(),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), _algorithm), // Creates the signing credentials
            Issuer = _issuer,
            Audience = _audience,
        };

        if (_header.Count > 0)
        {
            tokenDescription.AdditionalHeaderClaims = _header; // Adds information to the header
        }

        var token = tokenHandler.CreateToken(tokenDescription);
        return tokenHandler.WriteToken(token);
    }

    /// <summary>
    /// Extracts claims from a JWT token.
    /// </summary>
    /// <param name="token">The JWT token.</param>
    /// <returns>A list of claims extracted from the token.</returns>
    public List<Claim> GetClaimsFromToken(string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            throw new ArgumentException("The token cannot be null or empty.", nameof(token));
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_secret)),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ClockSkew = TimeSpan.Zero
        };

        try
        {
            SecurityToken validatedToken;
            var principal = tokenHandler.ValidateToken(token, validationParameters, out validatedToken);
            return principal.Claims.ToList();
        }
        catch (Exception ex)
        {
            throw new Exception("Invalid token.", ex);
        }
    }

    /// <summary>
    /// Checks if a JWT token is expired.
    /// </summary>
    /// <param name="token">The JWT token.</param>
    /// <returns>True if the token is expired, false otherwise.</returns>
    public bool IsTokenExpired(string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            throw new ArgumentException("The token cannot be null or empty.", nameof(token));
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_secret)),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };

        try
        {
            SecurityToken validatedToken;
            tokenHandler.ValidateToken(token, validationParameters, out validatedToken);
            return false; // Token is not expired
        }
        catch (SecurityTokenExpiredException)
        {
            return true; // Token is expired
        }
        catch (Exception ex)
        {
            throw new Exception("Invalid token.", ex);
        }
    }

    /// <summary>
    /// Extracts the issuer from a JWT token.
    /// </summary>
    /// <param name="token">The JWT token.</param>
    /// <returns>The issuer of the token, or null if not found.</returns>
    public string GetIssuerFromToken(string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            throw new ArgumentException("The token cannot be null or empty.", nameof(token));
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_secret)),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ClockSkew = TimeSpan.Zero
        };

        try
        {
            SecurityToken validatedToken;
            var principal = tokenHandler.ValidateToken(token, validationParameters, out validatedToken);
            return principal.FindFirst(JwtRegisteredClaimNames.Iss)?.Value;
        }
        catch (Exception ex)
        {
            throw new Exception("Invalid token.", ex);
        }
    }

    /// <summary>
    /// Extracts the audience from a JWT token.
    /// </summary>
    /// <param name="token">The JWT token.</param>
    /// <returns>The audience of the token, or null if not found.</returns>
    public string GetAudienceFromToken(string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            throw new ArgumentException("The token cannot be null or empty.", nameof(token));
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_secret)),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ClockSkew = TimeSpan.Zero
        };

        try
        {
            SecurityToken validatedToken;
            var principal = tokenHandler.ValidateToken(token, validationParameters, out validatedToken);
            return principal.FindFirst(JwtRegisteredClaimNames.Aud)?.Value;
        }
        catch (Exception ex)
        {
            throw new Exception("Invalid token.", ex);
        }
    }

    /// <summary>
    /// Extracts the headers from a JWT token.
    /// </summary>
    /// <param name="token">The JWT token.</param>
    /// <returns>A dictionary containing the headers of the token.</returns>
    public Dictionary<string, object> GetHeadersFromToken(string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            throw new ArgumentException("The token cannot be null or empty.", nameof(token));
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_secret)),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ClockSkew = TimeSpan.Zero
        };

        try
        {
            SecurityToken validatedToken;
            var principal = tokenHandler.ValidateToken(token, validationParameters, out validatedToken);

            if (validatedToken is JwtSecurityToken jwtToken)
            {
                return new Dictionary<string, object>(jwtToken.Header);
            }
            else
            {
                throw new Exception("Invalid token format.");
            }
        }
        catch (Exception ex)
        {
            throw new Exception("Invalid token.", ex);
        }
    }

    private DateTime GetExpirationDate()
    {
        switch (_expirationType)
        {
            case ExpirationType.Minutes:
                return DateTime.UtcNow.AddMinutes(_expirationValue);
            case ExpirationType.Hours:
                return DateTime.UtcNow.AddHours(_expirationValue);
            case ExpirationType.Days:
                return DateTime.UtcNow.AddDays(_expirationValue);
            default:
                return DateTime.UtcNow.AddDays(7); // Default expiration of 7 days
        }
    }

    // Validates the claim name format
    private bool IsValidClaimName(string claimName)
    {
        if (string.IsNullOrEmpty(claimName))
        {
            return false;
        }

        // The claim name must start with a letter and can contain letters, numbers, underscores, and hyphens.
        return claimName.StartsWith("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", StringComparison.OrdinalIgnoreCase) &&
               claimName.All(c => char.IsLetterOrDigit(c) || c == '_' || c == '-');
    }
}