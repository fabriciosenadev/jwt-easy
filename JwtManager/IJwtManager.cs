using System.Security.Claims;

namespace JwtService;

/// <summary>
/// JWT token manager.
/// </summary>
public interface IJwtManager
{
    /// <summary>
    /// Starts the generation of a new JWT token.
    /// </summary>
    /// <param name="secret">The secret key to sign the token.</param>
    /// <returns>The current instance of `IJwtManager` for method chaining.</returns>
    IJwtManager StartGeneration(string secret);

    /// <summary>
    /// Adds claims to the JWT token.
    /// </summary>
    /// <param name="claims">A list of claims to be added to the token.</param>
    /// <returns>The current instance of `IJwtManager` for method chaining.</returns>
    IJwtManager WithClaims(List<KeyValuePair<string, string>> claims);

    /// <summary>
    /// Sets the expiration date of the JWT token.
    /// </summary>
    /// <param name="expirationType">The type of expiration (minutes, hours, days).</param>
    /// <param name="expirationValue">The expiration value. Default is 7 days.</param>
    /// <returns>The current instance of `IJwtManager` for method chaining.</returns>
    IJwtManager WithExpiration(ExpirationType expirationType, int expirationValue);

    /// <summary>
    /// Sets the issuer of the JWT token.
    /// </summary>
    /// <param name="issuer">The issuer of the token.</param>
    /// <returns>The current instance of `IJwtManager` for method chaining.</returns>
    IJwtManager WithIssuer(string issuer);

    /// <summary>
    /// Sets the audience of the JWT token.
    /// </summary>
    /// <param name="audience">The audience of the token.</param>
    /// <returns>The current instance of `IJwtManager` for method chaining.</returns>
    IJwtManager WithAudience(string audience);

    /// <summary>
    /// Sets the signing algorithm for the JWT token.
    /// </summary>
    /// <param name="algorithm">The signing algorithm. Default is HMAC SHA256.</param>
    /// <returns>The current instance of `IJwtManager` for method chaining.</returns>
    IJwtManager WithSigningAlgorithm(string algorithm);

    /// <summary>
    /// Adds additional information to the JWT token header.
    /// </summary>
    /// <param name="header">A dictionary of key-value pairs to be added to the header.</param>
    /// <returns>The current instance of `IJwtManager` for method chaining.</returns>
    IJwtManager WithHeader(Dictionary<string, object> header);

    /// <summary>
    /// Generates the JWT token.
    /// </summary>
    /// <returns>The generated JWT token.</returns>
    string GenerateToken();

    /// <summary>
    /// Extracts claims from a JWT token.
    /// </summary>
    /// <param name="token">The JWT token.</param>
    /// <returns>A list of claims extracted from the token.</returns>
    List<Claim> GetClaimsFromToken(string token);

    /// <summary>
    /// Checks if a JWT token is expired.
    /// </summary>
    /// <param name="token">The JWT token.</param>
    /// <returns>True if the token is expired, false otherwise.</returns>
    bool IsTokenExpired(string token);

    /// <summary>
    /// Extracts the issuer from a JWT token.
    /// </summary>
    /// <param name="token">The JWT token.</param>
    /// <returns>The issuer of the token, or null if not found.</returns>
    string GetIssuerFromToken(string token);

    /// <summary>
    /// Extracts the audience from a JWT token.
    /// </summary>
    /// <param name="token">The JWT token.</param>
    /// <returns>The audience of the token, or null if not found.</returns>
    string GetAudienceFromToken(string token);

    /// <summary>
    /// Extracts the headers from a JWT token.
    /// </summary>
    /// <param name="token">The JWT token.</param>
    /// <returns>A dictionary containing the headers of the token.</returns>
    Dictionary<string, object> GetHeadersFromToken(string token);

    // Código que já existe

    /// <summary>
    /// Gets the configured claims for the JWT token.
    /// </summary>
    /// <returns>A list of configured claims.</returns>
    List<KeyValuePair<string, string>> GetClaims();

    /// <summary>
    /// Gets the configured issuer for the JWT token.
    /// </summary>
    /// <returns>The configured issuer.</returns>
    string GetIssuer();

    /// <summary>
    /// Gets the configured audience for the JWT token.
    /// </summary>
    /// <returns>The configured audience.</returns>
    string GetAudience();

    /// <summary>
    /// Gets the configured signing algorithm for the JWT token.
    /// </summary>
    /// <returns>The configured signing algorithm.</returns>
    string GetSigningAlgorithm();

    /// <summary>
    /// Gets the configured header for the JWT token.
    /// </summary>
    /// <returns>A dictionary containing the configured header.</returns>
    Dictionary<string, object> GetHeader();

    /// <summary>
    /// Gets the configured expiration date for the JWT token.
    /// </summary>
    /// <returns>The configured expiration date.</returns>
    DateTime GetConfiguredExpirationDate();
}
