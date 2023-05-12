using JWT;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Exceptions;
using JWT.Serializers;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TestJwt {
    public class JwtNetHelper {
        static string SecretKey => ConfigurationManager.AppSettings["AppSecret"];
        static string Issuer => ConfigurationManager.AppSettings["Issuer"];
        static string Audience => ConfigurationManager.AppSettings["Audience"];
        static string ExpiredMinutes => ConfigurationManager.AppSettings["ExpiredMinutes"];


        public static string GeneratteToken(int expiredMinute = 1) {

            if (!string.IsNullOrWhiteSpace(ExpiredMinutes)) {
                int.TryParse(ExpiredMinutes, out expiredMinute);
            }

            //var permClaims = new Dictionary<string, object>
            //{
            //    {
            //        "jti", DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            //    },
            //    {
            //        "iss", JwtIssuer
            //    },
            //    {
            //        "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            //    },
            //    {
            //        "exp", DateTimeOffset.UtcNow.AddSeconds(expiredMinute).ToUnixTimeSeconds()
            //    }
            //};

            var tokenStr = JwtBuilder.Create()
                      .WithSecret(SecretKey)
                      .WithAlgorithm(new HMACSHA256Algorithm())
                      .WithVerifySignature(true)
                      //.AddClaims(permClaims)
                      .Audience(Audience)
                      .Issuer(Issuer)
                      .IssuedAt(DateTimeOffset.UtcNow.ToUnixTimeSeconds())
                      .ExpirationTime(DateTime.UtcNow.AddMinutes(expiredMinute))
                      .Id(Guid.NewGuid())
                      .Encode();

            return tokenStr;
        }

        public static AuthResult AuthToken(string token) {

            var authResult = new AuthResult();

            if (string.IsNullOrWhiteSpace(token)) {
                authResult.Message = "token参数为空";
                authResult.IsAuthenticated = false;
                return authResult;
            }

            token = token.Replace("Bearer ", string.Empty);


            try {
                //IJsonSerializer serializer = new JsonNetSerializer();
                //IDateTimeProvider provider = new UtcDateTimeProvider();
                //IJwtValidator validator = new JwtValidator(serializer, provider);
                //IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
                //IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
                //IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder, algorithm);

                //var json = decoder.Decode(token, Encoding.UTF8.GetBytes(SecretKey));


                var json = JwtBuilder.Create()
                     .WithAlgorithm(new HMACSHA256Algorithm())
                     .WithSecret(SecretKey)
                     .WithValidationParameters(t => {
                         t.ValidateExpirationTime = true;
                         t.ValidateIssuedTime = true;
                         t.ValidateSignature = true;
                     })
                     .Decode(token);

                authResult.Message = "token 认证成功";
                authResult.IsAuthenticated = true;
                return authResult;
            }
            catch (TokenNotYetValidException) {

                authResult.Message = "token 未认证";
                authResult.IsAuthenticated = false;
                return authResult;
            }
            catch (TokenExpiredException) {

                authResult.Message = "token 已过期";
                authResult.IsAuthenticated = false;
                return authResult;
            }
            catch (SignatureVerificationException) {

                authResult.Message = "token 签名错误";
                authResult.IsAuthenticated = false;
                return authResult;
            }
        }
    }
}
