using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using OAuthWithController.Models;
using OAuthWithController.provider;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace OAuthWithController
{
    public partial class Startup
    {
        public static OAuthAuthorizationServerOptions OAuthOptions { get; private set; }
        public static string PublicClientId { get; private set; }

        public void ConfigureAuth(IAppBuilder app)
        {
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            PublicClientId = "self";
            OAuthOptions = new OAuthAuthorizationServerOptions
            {
                TokenEndpointPath = new PathString("/token"),
                Provider = new OAuthAppProvider(PublicClientId),
                AuthorizeEndpointPath = new PathString("/api/Account/GetExternalLogin"),
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(10),
                AllowInsecureHttp = false
            };

            app.UseOAuthBearerTokens(OAuthOptions);
        }
    }
}