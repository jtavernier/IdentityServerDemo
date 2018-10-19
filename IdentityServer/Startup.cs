using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using IdentityServer4;

namespace IdentityServerDemo
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication()
                 .AddOpenIdConnect("AAD", options =>
                 {
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    options.Authority = "https://login.microsoftonline.com/<YOUR_TENANT_ID>";
                    options.ResponseType = "id_token";
                    options.CallbackPath = "/signin-oidc";
                    options.ClientId = "<YOUR_CLIENT_ID>";
                    options.ClientSecret = "<YOUR_CLIENT_SECRET>";
                 });
            
            services.AddIdentityServer()
                .AddDeveloperSigningCredential()
                //For this example with use InMemoryStores instead of a database
                .AddInMemoryApiResources(Config.GetApiResources())
                .AddInMemoryClients(Config.GetClients())
                .AddInMemoryIdentityResources(Config.GetIdentityResources());

             services.AddMvc();
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseIdentityServer();
            app.UseMvcWithDefaultRoute();            
        }
    }
}
