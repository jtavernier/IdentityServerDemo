using System.Collections.Generic;
using IdentityServer4;
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
           
            var clients = new List<Client>();
            
            //Example 1 : Client Credentials with ConsoleApp1
            clients.Add(new Client{
                    ClientId = "console-client",
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    },

                    AllowedScopes = { "api1" }
                });


            //Example 2 : Implicit Workflow with Mvc1    
            var mvc =  new Client{
                    ClientId = "mvc",
                    ClientName = "MVC Client",
                    AllowedGrantTypes = GrantTypes.Implicit,
                    RedirectUris = { "http://localhost:5002/signin-oidc" },
                    PostLogoutRedirectUris = { "http://localhost:5002/signout-callback-oidc" },
                    AllowedScopes = new List<string>{
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile
                    }
                    
                };

            mvc.IdentityProviderRestrictions.Add("AAD");
            mvc.RequireConsent = false;
            mvc.EnableLocalLogin = false;

            clients.Add(mvc);

            return clients;
        }

        public static IEnumerable<IdentityResource> GetIdentityResources() {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
            };
        }
    }



}