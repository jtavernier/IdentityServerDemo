using System.Collections.Generic;
using IdentityServer4.Models;

namespace IdentityServerDemo
{
    public class Config 
    {
        public static IEnumerable<ApiResource> GetApiResources(){
            return new List<ApiResource>{
                new ApiResource("api1", "My API")
            };
        }

        public static IEnumerable<Client> GetClients(){
            return new List<Client>{
                new Client{
                    ClientId = "console-client",
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    },

                    AllowedScopes = { "api1" }
                }
            };
        }
    }



}