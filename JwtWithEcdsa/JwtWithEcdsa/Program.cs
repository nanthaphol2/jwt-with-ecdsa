using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JwtWithEcdsa
{
    internal class Program
    {
        // Curve and algorithm
        //{ ECCurve.NamedCurves.nistP256, "ES256" },
        //{ ECCurve.NamedCurves.nistP384, "ES384" },
        //{ ECCurve.NamedCurves.nistP521, "ES512" }

        static void Main(string[] args)
        {

            //openssl ecparam -name prime256v1 -genkey -noout -out ec_private.pem
            //openssl ec -in ec_private.pem -pubout -out ec_public.pem
            //openssl pkcs8 -topk8 -nocrypt -in ec_private.pem -out private_key_pkcs8.pem

            string publicKey = @"-----BEGIN PUBLIC KEY-----
#########################
-----END PUBLIC KEY-----";

            string privateKey = @"-----BEGIN PRIVATE KEY-----
#########################
-----END PRIVATE KEY-----";

            // Load the private key using BouncyCastle
            var privateKeyParam = LoadPrivateKey(privateKey);

            // Create ECDsa object from private key parameters
            var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = privateKeyParam.D.ToByteArrayUnsigned(),
                Q = new ECPoint
                {
                    X = privateKeyParam.Parameters.G.AffineXCoord.ToBigInteger().ToByteArrayUnsigned(),
                    Y = privateKeyParam.Parameters.G.AffineYCoord.ToBigInteger().ToByteArrayUnsigned()
                }
            });

            // Create SecurityKey and SigningCredentials
            var securityKey = new ECDsaSecurityKey(ecdsa);
            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256);

            // Create JWT Token
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = "me",
                Audience = "you",
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, "username"),
                    new Claim(ClaimTypes.Role, "role")
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = signingCredentials
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            string jwtToken = tokenHandler.WriteToken(token);

            Console.WriteLine("Generated JWT Token: ");
            Console.WriteLine(jwtToken);

            //var (privateKey, publicKey) = CreateKeys(ECCurve.NamedCurves.nistP256);

            //var jwt = CreateSignedJwt(privateKey, "ES256");
            ValidateJwtToken(jwtToken, publicKey);
        }

        private static ECPrivateKeyParameters LoadPrivateKey(string privateKeyPem)
        {
            using (var reader = new StringReader(privateKeyPem))
            {
                var pemReader = new PemReader(reader);
                return (ECPrivateKeyParameters)pemReader.ReadObject();
            }
        }

        private static ECPublicKeyParameters LoadPublicKey(string publicKeyPem)
        {
            using (var reader = new StringReader(publicKeyPem))
            {
                var pemReader = new PemReader(reader);
                return (ECPublicKeyParameters)pemReader.ReadObject();
            }
        }

        private static void ValidateJwtToken(string token, string publicKey)
        {
            var publicKeyParam = LoadPublicKey(publicKey);

            // Create ECDsa object from public key parameters
            var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = publicKeyParam.Q.XCoord.ToBigInteger().ToByteArrayUnsigned(),
                    Y = publicKeyParam.Q.YCoord.ToBigInteger().ToByteArrayUnsigned()
                }
            });

            var securityKey = new ECDsaSecurityKey(ecdsa);

            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = "me",
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = securityKey
            };

            try
            {
                var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
                Console.WriteLine("Token is valid.");
                // Extract claims or perform further validation if needed
            }
            catch (Exception ex)
            {
                Console.WriteLine("Token validation failed: " + ex.Message);
            }
        }
    }
}
