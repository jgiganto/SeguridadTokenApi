using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.Owin.Security.OAuth;
using System.Threading.Tasks;
using System.Security.Claims;
using SeguridadTokenApi.Models;

namespace SeguridadTokenApi.Credentials
{
    public class AutorizacionCredencialesToken:OAuthAuthorizationServerProvider
    {
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });
            
            using (EntidadEmpleados db = new EntidadEmpleados())
            {
                
                int empno = int.Parse(context.Password);
                var empleado = db.EMP.FirstOrDefault(z => z.APELLIDO == context.UserName && z.EMP_NO == empno);
                 
                if (empleado == null)
                {
                    context.SetError("Acceso denegado", "El usuario/password son incorrectos.");
                    return;
                }
                ClaimsIdentity identidad = new ClaimsIdentity(context.Options.AuthenticationType);
                identidad.AddClaim(new Claim(ClaimTypes.Name, context.Password));
                identidad.AddClaim(new Claim(ClaimTypes.Role, "EMPLEADO"));
                context.Validated(identidad);
                 
            }

        }
    }
}