using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

namespace TestJwt {
    class Program {
        static void Main(string[] args) {

            //AuthToken();
            AuthTokenByJwtNet();

            //TestConnection();

            Console.ReadKey();

        }

        private static void GetAccountList() {
            try {

                var jwtToken = JwtHelper.GenerateToken();

                Console.WriteLine($"jwt token = {jwtToken}");

                var logPath = System.IO.Path.Combine(AppContext.BaseDirectory, $"{DateTime.Now.ToString("yyyy-MM-dd")}.log");
                if (!System.IO.File.Exists(logPath)) {
                    var stream = System.IO.File.Create(logPath);
                    stream.Close();
                    stream.Dispose();
                }
                System.IO.File.AppendAllText(logPath, DateTime.Now.ToString(), Encoding.UTF8);
                System.IO.File.AppendAllText(logPath, "\r\n", Encoding.UTF8);
                System.IO.File.AppendAllText(logPath, jwtToken, Encoding.UTF8);
                System.IO.File.AppendAllText(logPath, "\r\n", Encoding.UTF8);

                // 发送HTTP请求，并在Header中添加Authorization字段和JWT Token
                var client = new HttpClient();
                client.BaseAddress = new Uri(ConfigurationManager.AppSettings["IdmBaseUrl"]);
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwtToken);
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));//accept header

                var requestUrl = "account/list";
                var pageIndex = "1";
                var pageSize = "5";

                var startTime = (long)(DateTime.Now.ToUniversalTime() - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;//Unix时间戳的毫秒值

                var paramDict = new Dictionary<string, string>();
                paramDict.Add("page", pageIndex);
                paramDict.Add("size", pageSize);
                paramDict.Add("startTime", startTime.ToString());

                var contentStr = JsonConvert.SerializeObject(paramDict);

                Console.WriteLine($"post json = {contentStr}");

                var request = new HttpRequestMessage(HttpMethod.Post, requestUrl) {
                    Content = new StringContent(contentStr, Encoding.UTF8, "application/json")
                };
                var response = client.SendAsync(request).Result;

                string content;
                if (response.IsSuccessStatusCode) {
                    content = response.Content.ReadAsStringAsync().Result;
                }
                else {
                    content = $"error {response.StatusCode}, {response.ReasonPhrase}";
                }

                client.Dispose();


                Console.WriteLine(content);
            }
            catch (Exception ex) {
                Console.WriteLine("InnerException");

                Console.WriteLine(ex?.InnerException?.Message);
                Console.WriteLine(ex?.InnerException?.StackTrace);

                Console.WriteLine("Exception");
                Console.WriteLine(ex?.Message);
                Console.WriteLine(ex?.StackTrace);
            }
        }

        private static void TestConnection() {

            try {

                var jwtToken = JwtHelper.GenerateToken();
                var requestUrl = string.Format(ConfigurationManager.AppSettings["TestConnectionUrl"], $"Bearer {jwtToken}");

                // 发送HTTP请求，并在Header中添加Authorization字段和JWT Token
                var client = new HttpClient();
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwtToken);
                var response = client.GetAsync(requestUrl).Result;

                string content;
                if (response.IsSuccessStatusCode) {
                    content = response.Content.ReadAsStringAsync().Result;
                }
                else {
                    content = $"error {response.StatusCode}, {response.ReasonPhrase}";
                }

                client.Dispose();

                Console.WriteLine(content);
            }
            catch (Exception ex) {

                Console.WriteLine($"error {ex?.Message}");
            }
        }



        private static void AuthToken() {

            var tokenStr = JwtHelper.GenerateToken();

            Console.WriteLine($"token={tokenStr}");

            var authResult = JwtHelper.AuthToken(tokenStr);

            Console.WriteLine($"auth result={authResult.IsAuthenticated},{authResult.Message}");
        }

        private static void AuthTokenByJwtNet() {
            var tokenStr = JwtNetHelper.GeneratteToken();

            Console.WriteLine($"token={tokenStr}");

            var authResult= JwtNetHelper.AuthToken(tokenStr);

            Console.WriteLine($"auth result={authResult.IsAuthenticated},{authResult.Message}");
        }
    }
}
