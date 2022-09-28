using JWTAuth.WebApi.Models;
using System.Security.Claims;

namespace JWTAuth.WebApi.Interface
{
    public interface IJWTManagerRepository
    {
        Tokens GenerateToken(string userName);
        Tokens GenerateRefreshToken(string userName);
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    }
}
