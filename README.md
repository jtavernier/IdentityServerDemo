# Getting Started
Identity Server Demo demonstrates how to expose an OpenID/OAuth2 endpoint using IdentityServer4 with AAD as an Identity Provider. 

It includes examples for the followings workflows :
- Client Credential (Server to server)
- Implicit (Authenticate user using AAD)
- Integrate an API with PowerQuery

For more info please refer to IdentityServer 4 docs and tutorials [here](http://docs.identityserver.io/en/release/quickstarts/0_overview.html).

>To make it simple we use InMemoryStore instead of Database, if you're interested in storing your configuration using a SQL Db please refer to this [doc](http://docs.identityserver.io/en/release/quickstarts/8_entity_framework.html)

>Create/Update Clients and Resources through the Config.cs

## Example 1 : Client Credentials 
*See Identity Server 4 Tutorial on Client Credentials [here](http://docs.identityserver.io/en/release/quickstarts/1_client_credentials.html)*

In this example we want to protect an API *Api1* and give access to another program *ConsoleApp1*

### Steps:
- Run *IdentityServer* - *Default Port 5010*
- Run *SampleApps/Api1* - *Default Port 5001*
- Run *SamplesApps/ConsoleApp1*

> AAD is not required for that scenario as all the config is stored within Identity Server

## Example 2 : Implicit using AAD
*See Identity Server 4 Tutorial on Implicit Workflow [here](http://docs.identityserver.io/en/release/quickstarts/1_client_credentials.html) and External Providers [here](http://docs.identityserver.io/en/release/quickstarts/4_external_authentication.html)*

In this case we will use a MVC Application *Mvc1* which want to authenticate it users against AAD 

### Steps
- First you need to create a new Application Registration in your AAD and generate a new key. Note you AppId, Key and TenantId
- In the Startup.cs Update AAD Configuration ClientId/ClientSecret and Azure Subscription address with you info
- A MVC application have already been set up in the Config.cs (Notice that it has been restricted to use AAD)
- Run *IdentityServer* - *(Default - Port 5010)*
- Run *MVC1* - *(Default - Port 5002)*
- Naviguate to localhost:5002 and try to access the "Restricted Page"
- You should be redirected to AAD to authenticate

## Example 3 : Integrate an API with PowerQuery

To integrate an API with PowerQuery:

Configure bearer tokens in your startup as:

```
.AddJwtBearer(
                    JwtBearerDefaults.AuthenticationScheme,
                    options =>
                        {
                            options.Authority = Config.AuthorizationUrl; // The URL of the identity provider
                            options.Audience = Config.BearerTokenAudience; // The url of this website
                            options.TokenValidationParameters.ValidateLifetime = true;
                            options.TokenValidationParameters.ClockSkew = TimeSpan.Zero;
                            options.Events = new JwtBearerEvents()
                                                 {
                                                     OnChallenge = async context =>
                                                         {
                                                             var httpContext = context.HttpContext;

                                                             // Excel has very specific requirements about how it will process the 401 in order to use bearer tokens, this header is essential
                                                             httpContext.Response.Headers.Add(@"WWW-Authenticate", $"Bearer authorization_uri=\"{Config.AuthorizationUrl}\"");
                                                             httpContext.Response.StatusCode = 401;
                                                             context.HandleResponse();
                                                             await Task.CompletedTask;
                                                         }
                                                 };
                        });
```

Add some way to challenge using that authentication scheme such as (only way I could find to do this was via query string):
```
                                context.Result = new ChallengeResult(JwtBearerDefaults.AuthenticationScheme);
                                return;
```







