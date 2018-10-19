# Getting Started
Identity Server Demo demonstrates how to expose your own OpenID/OAuth2 endpoint using IdentityServer4 and AAD as an Identity Provider. 

It includes examples for the followings workflows :
- Client Credential (Server to server)
- Implicit (Authenticate user using AAD)
- Hybrid (Client Credential + Implicit)

For more info please refer to IdentityServer 4 docs and tutorials [here](http://docs.identityserver.io/en/release/quickstarts/0_overview.html).

>To make it simple we use InMemoryStore instead of Database, if you're interested in storing your configuration using a SQL Db please refer to this [doc](http://docs.identityserver.io/en/release/quickstarts/8_entity_framework.html)

>Create/Update Clients and Resources through the Config.cs

## Example 1 : Client Credentials 
*See Identity Server 4 Tutorial [here](http://docs.identityserver.io/en/release/quickstarts/1_client_credentials.html)*

In this example we want to protect an API *Api1* and give access to another program *ConsoleApp1*

### Steps:
- Run *IdentityServer*
- Run *SampleApps/Api1*
- Run *SamplesApps/ConsoleApp1*

## Example 2 : Implicit






