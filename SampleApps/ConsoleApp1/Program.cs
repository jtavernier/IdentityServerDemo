using IdentityModel.Client;
using Newtonsoft.Json.Linq;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            // discover endpoints from metadata
            var disco = DiscoverEndpoint().ConfigureAwait(false).GetAwaiter().GetResult();

            // request token
            var tokenResponse = RequestToken(disco).ConfigureAwait(false).GetAwaiter().GetResult();

            // call api
            var content = CallApi1(tokenResponse).ConfigureAwait(false).GetAwaiter().GetResult();

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        public static async Task<DiscoveryResponse> DiscoverEndpoint()
        {
           
            var disco = await DiscoveryClient.GetAsync("http://localhost:5010");
            if (disco.IsError)
            {
                Console.WriteLine(disco.Error);
                throw new Exception();
            }

            return disco;
        }

        public static async Task<TokenResponse> RequestToken(DiscoveryResponse disco)
        {
            while (true)
            {
                Console.WriteLine("Getting client token...");
                var tokenClient = new TokenClient(disco.TokenEndpoint, "console-client", "secret");
                var tokenResponse = await tokenClient.RequestClientCredentialsAsync("api1");

                if (tokenResponse.IsError)
                {
                    Console.WriteLine(tokenResponse.Error);
                    Console.WriteLine("Failed to get token. Press any key to retry.");
                    Console.ReadKey();
                }
                else
                {
                    //You can copy and paste the access token from the console to jwt.io to inspect the raw token. 
                    Console.WriteLine(tokenResponse.Json);
                    return tokenResponse;
                }
            }

        }

        public static async Task<string> CallApi1(TokenResponse tokenResponse)
        {
            var client = new HttpClient();
            client.SetBearerToken(tokenResponse.AccessToken);
            Console.WriteLine("Making request to protected API...");
            var response = await client.GetAsync("http://localhost:5001/identity");
            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine(response.StatusCode);
                throw new Exception();
            }
            else
            {
                var content = await response.Content.ReadAsStringAsync();
                Console.WriteLine(JArray.Parse(content));
                return content;
            }
        }
    }
}
