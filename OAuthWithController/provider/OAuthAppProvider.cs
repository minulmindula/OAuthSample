using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using OAuthWithController.Models;
using OAuthWithController.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace OAuthWithController.provider
{
    public class OAuthAppProvider : OAuthAuthorizationServerProvider
    {
        //public override Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        //{
        //    return Task.Factory.StartNew(() =>
        //    {
        //        var username = context.UserName;
        //        var password = context.Password;
        //        var userService = new UserService();
        //        User user = userService.GetUserByCredentials(username, password);
        //        if (user != null)
        //        {
        //            var claims = new List<Claim>()
        //            {
        //                new Claim(ClaimTypes.Name, user.Name),
        //                new Claim("UserID", user.Id)
        //            };

        //            ClaimsIdentity oAutIdentity = new ClaimsIdentity(claims, Startup.OAuthOptions.AuthenticationType);
        //            context.Validated(new AuthenticationTicket(oAutIdentity, new AuthenticationProperties() { }));

        //            AuthenticationProperties properties = CreateProperties(user.UserName);
        //            AuthenticationTicket ticket = new AuthenticationTicket(oAuthIdentity, properties);
        //            context.Validated(ticket);
        //            context.Request.Context.Authentication.SignIn(cookiesIdentity);
        //        }
        //        else
        //        {
        //            context.SetError("invalid_grant", "Error");
        //        }
        //    });
        //}

        //public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        //{
        //    if (context.ClientId == null)
        //    {
        //        context.Validated();
        //    }
        //    return Task.FromResult<object>(null);
        //}

        private readonly string _publicClientId;

        public OAuthAppProvider(string publicClientId)
        {
            if (publicClientId == null)
            {
                throw new ArgumentNullException("publicClientId");
            }

            _publicClientId = publicClientId;
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            var userManager = context.OwinContext.GetUserManager<ApplicationUserManager>();

            ApplicationUser user = await userManager.FindAsync(context.UserName, context.Password);

            if (user == null)
            {
                context.SetError("invalid_grant", "The user name or password is incorrect.");
                return;
            }

            ClaimsIdentity oAuthIdentity = await user.GenerateUserIdentityAsync(userManager,
               OAuthDefaults.AuthenticationType);
            ClaimsIdentity cookiesIdentity = await user.GenerateUserIdentityAsync(userManager,
                CookieAuthenticationDefaults.AuthenticationType);

            AuthenticationProperties properties = CreateProperties(user.UserName);
            AuthenticationTicket ticket = new AuthenticationTicket(oAuthIdentity, properties);
            context.Validated(ticket);
            context.Request.Context.Authentication.SignIn(cookiesIdentity);

            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });
        }

        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            return Task.FromResult<object>(null);
        }

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            // Resource owner password credentials does not provide a client ID.
            if (context.ClientId == null)
            {
                context.Validated();
            }

            return Task.FromResult<object>(null);
        }

        public override Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            if (context.ClientId == _publicClientId)
            {
                Uri expectedRootUri = new Uri(context.Request.Uri, "/");

                if (expectedRootUri.AbsoluteUri == context.RedirectUri)
                {
                    context.Validated();
                }
            }

            return Task.FromResult<object>(null);
        }

        public static AuthenticationProperties CreateProperties(string userName)
        {
            IDictionary<string, string> data = new Dictionary<string, string>
            {
                { "userName", userName }
            };
            return new AuthenticationProperties(data);
        }
    }
}