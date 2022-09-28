using JWTAuth.WebApi.Models;
using MongoDB.Driver;
using System;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;
using MongoDB.Bson;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace JWTAuth.WebApi.Services
{
    public class UserService
    {
        private readonly IMongoCollection<User> users;
        private IConfiguration _config;
        public UserService(IConfiguration config){
            var client = new MongoClient(config.GetConnectionString("Authorize"));
            var database = client.GetDatabase("Authorize");
            users = database.GetCollection<User>("Users");
            this._config = config;
         }
        public List<User> GetUsers() => users.Find(user => true).ToList();

        public User GetUser(string Id) => users.Find<User>(user=>user.id == Id).FirstOrDefault();

        public User Create(User user)
        {
            var hashsalt = EncryptPassword(user.password);
            User usr = new User();
            usr.id = ObjectId.GenerateNewId().ToString() ;
            usr.name = user.name;
            usr.email = user.email;
            usr.password = hashsalt.Hash;
            usr.salt = Convert.ToBase64String(hashsalt.Salt);
            users.InsertOne(usr);
            return usr;
        }

        [Obsolete]
        public Tokens Authenticate(String email,String password)
        {
            var em = this.users.Find(user => user.email == email).FirstOrDefault();
            if (em == null)
            {

                return null;
            }
            else
            {
                bool isPasswordMatch = VerifyPassword(password, Convert.FromBase64String(em.salt), em.password);
                if (isPasswordMatch)
                {
                    User usr = new User();
                    var Tokenhandle = new JwtSecurityTokenHandler();
                    var TokenKey = Encoding.ASCII.GetBytes(_config.GetSection("Jwt:key").Value);
                    var TokenDescriptor = new SecurityTokenDescriptor()
                    {
                        Subject = new ClaimsIdentity(new Claim[]
                        {
                            new Claim(ClaimTypes.Email,email),
                        }),
                        Audience= _config.GetSection("Jwt:Audience").Value,
                        Issuer = _config.GetSection("Jwt:Issuer").Value,
                        Expires = DateTime.UtcNow.AddMinutes(1),
                        SigningCredentials = new SigningCredentials(
                            new SymmetricSecurityKey(TokenKey),
                            SecurityAlgorithms.HmacSha256Signature)
                    };
                    var token = Tokenhandle.CreateToken(TokenDescriptor);
                    var refreshToken = GenerateRefreshToken();
                    em.refreshToken = refreshToken;
                    users.ReplaceOne(item => item.email == email,
                        em,
                         new UpdateOptions { IsUpsert = true });

                    return new Tokens { Access_Token = Tokenhandle.WriteToken(token), Refresh_Token = refreshToken };
                   
                }
                else
                    return null;
            }
           
        }

        [Obsolete]
        public Tokens Refresh(Tokens token)
        {
            var principal = GetPrincipalFromExpiredToken(token.Access_Token);
            var username = (JwtSecurityToken)principal;
            var email = username.Claims.First(x => x.Type == "email").Value;
            var savedrefresh = this.users.Find(user => user.email == email && user.refreshToken == token.Refresh_Token).FirstOrDefault();
            if (savedrefresh.refreshToken != token.Refresh_Token)
            {
                return null;
            }
            var newJwtToken = GenerateRefreshToken(email);
            if (newJwtToken == null)
            {
                return null;
            }
            var usr = this.users.Find(user => user.email == email).FirstOrDefault();
            usr.refreshToken = newJwtToken.Refresh_Token;
            users.ReplaceOne(item => item.email == email,
                      usr,
                       new UpdateOptions { IsUpsert = true });
            return newJwtToken;

        }
        public Tokens GenerateRefreshToken(string email)
        {
            return GenerateJWTTokens(email);
        }
        public Tokens GenerateJWTTokens(string email)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var tokenKey = Encoding.UTF8.GetBytes(_config["JWT:Key"]);
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                  {
                     new Claim(ClaimTypes.Email,email)
                  }),
                    Expires = DateTime.Now.AddHours(1),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature)
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var refreshToken = GenerateRefreshToken();
                return new Tokens { Access_Token = tokenHandler.WriteToken(token), Refresh_Token = refreshToken };
            }
            catch (Exception ex)
            {
                return null;
            }
        }
        public JwtSecurityToken GetPrincipalFromExpiredToken(string token)
        {
            var Key = Encoding.UTF8.GetBytes(_config["JWT:Key"]);

            var tokenValidationParameters = new TokenValidationParameters
            {

                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Key),
                ClockSkew = TimeSpan.Zero,
                ValidIssuer = _config["JWT:Issuer"],
                ValidAudience = _config["JWT:Audience"]


            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            JwtSecurityToken jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }


            return jwtSecurityToken;
        }
        public bool VerifyPassword(string enteredPassword, byte[] salt, string storedPassword)
        {
            string encryptedPassw = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: enteredPassword,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA1,
                iterationCount: 10000,
                numBytesRequested: 256 / 8
            ));
            return encryptedPassw == storedPassword;
        }

        public hash_salt EncryptPassword(string password)
        {
            byte[] salt = new byte[128 / 8]; // Generate a 128-bit salt using a secure PRNG
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            string encryptedPassw = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA1,
                iterationCount: 10000,
                numBytesRequested: 256 / 8
            ));
            return new hash_salt { Hash = encryptedPassw, Salt = salt };
        }
        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }
    }
}
