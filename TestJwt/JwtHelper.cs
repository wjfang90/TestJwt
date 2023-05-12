using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace TestJwt {
    public class JwtHelper {

        static string SecretKey => ConfigurationManager.AppSettings["AppSecret"]; 
        static string Issuer => ConfigurationManager.AppSettings["Issuer"];
        static string Audience => ConfigurationManager.AppSettings["Audience"];
        static string ExpiredMinutes => ConfigurationManager.AppSettings["ExpiredMinutes"];

        public static string GenerateToken(int expiredMinute = 1) {

            if (!string.IsNullOrWhiteSpace(ExpiredMinutes)) {
                int.TryParse(ExpiredMinutes, out expiredMinute);
            }

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecretKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var permClaims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            };

            var token = new JwtSecurityToken(
                issuer: string.IsNullOrWhiteSpace(Issuer) ? null : Issuer,
                audience: string.IsNullOrWhiteSpace(Audience) ? null : Audience,
                permClaims,
                expires: DateTime.UtcNow.AddMinutes(expiredMinute),
                signingCredentials: credentials);

            var tokenStr = new JwtSecurityTokenHandler().WriteToken(token);
            return tokenStr;
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="token">token包含 Bearer 前缀和空格</param>
        public static AuthResult AuthToken(string token) {

            var authResult = new AuthResult();

            if (string.IsNullOrWhiteSpace(token)) {
                authResult.Message = "token参数为空";
                authResult.IsAuthenticated = false;
                return authResult;
            }

            token = token.Replace("Bearer ", string.Empty);

            try {

                var tokenHandler = new JwtSecurityTokenHandler();

                var decodedToken = tokenHandler.ReadJwtToken(token);

                Console.WriteLine($"token issueAt Time = {decodedToken.ValidFrom}");
                Console.WriteLine($"token Expired Time = {decodedToken.ValidTo}");
                Console.WriteLine($"current Time = {DateTime.UtcNow}");

                var isExpired = (DateTime.UtcNow - decodedToken.ValidTo).TotalSeconds > 0;

                if (isExpired) {
                    authResult.Message = "token 已过期";
                    authResult.IsAuthenticated = false;
                    return authResult;
                }

                var tokenParameters = new TokenValidationParameters {
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = string.IsNullOrWhiteSpace(Issuer) ? null : Issuer,
                    ValidAudience = string.IsNullOrWhiteSpace(Audience) ? null : Audience,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecretKey)),
                    ValidateIssuer = !string.IsNullOrWhiteSpace(Issuer),
                    ValidateAudience = !string.IsNullOrWhiteSpace(Audience),
                    ValidateLifetime = true,
                    ClockSkew= TimeSpan.FromSeconds(0) // 设置ClockSkew以避免默认的5分钟偏移
                };

                var claims = tokenHandler.ValidateToken(token, tokenParameters, out var decodedTokenTmp);

                // check if token is valid
                var isAuthenticated = claims.Identity.IsAuthenticated;

                authResult.Message = "token 认证成功";
                authResult.IsAuthenticated = isAuthenticated;
                return authResult;
            }
            catch (Exception ex) {

                Console.WriteLine($"authenticate error {ex?.Message}");
                Console.WriteLine($"authenticate error {ex?.InnerException?.Message}");

                authResult.Message = "token 认证错误";
                authResult.IsAuthenticated = false;
                return authResult;
            }

        }
    }
}
