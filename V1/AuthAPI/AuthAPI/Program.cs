using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Win32;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

#region mTLS
// Select certificate prompt
builder.WebHost.ConfigureKestrel(options =>
{
    options.ConfigureHttpsDefaults(o =>
    {
        o.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
        o.SslProtocols =
            System.Security.Authentication.SslProtocols.Tls12 |
            System.Security.Authentication.SslProtocols.Tls13;
        o.CheckCertificateRevocation = true;
    });
});
// Select certificate prompt
builder.Logging.AddConsole();

// Enable Certificate Authentication
builder.Services
    .AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
    .AddCertificate(options =>
    {
        options.AllowedCertificateTypes = CertificateTypes.All;
        options.ValidateCertificateUse = true;
        options.RevocationMode = X509RevocationMode.NoCheck;

        options.Events = new CertificateAuthenticationEvents
        {
            OnCertificateValidated = context =>
            {
                var cert = context.ClientCertificate;

                var claims = new[]
                {
                    new Claim(ClaimTypes.Name, context.ClientCertificate.Subject)
                };

                context.Principal = new ClaimsPrincipal(
                    new ClaimsIdentity(claims, context.Scheme.Name));

                // Expiry validation
                if (DateTime.UtcNow.AddDays(10) < cert.NotBefore ||
                    DateTime.UtcNow.AddDays(10) > cert.NotAfter)
                {
                    context.Fail("Certificate expired or not yet valid");
                    return Task.CompletedTask;
                }

                // Issuer validation
                if (!cert.Issuer.Contains("CN=mTLSCert"))
                {
                    context.Fail("Untrusted certificate issuer");
                    return Task.CompletedTask;
                }

                // Revocation validation
                if (!ValidateCertificateRevocation(cert))
                {
                    context.Fail("Certificate revoked");
                    return Task.CompletedTask;
                }

                // Validate thumbprint (IMPORTANT)
                if (cert.Thumbprint != "e82b697f3b4aa1680f9890a140349dceba3000f8")
                {
                    context.Fail("Invalid Certificate");
                    return Task.CompletedTask;
                }

                // All checks passed
                context.Success();
                return Task.CompletedTask;
            }
        };
    });

bool ValidateCertificateRevocation(X509Certificate2 cert)
{
    using var chain = new X509Chain();

    chain.ChainPolicy = new X509ChainPolicy
    {
        RevocationMode = X509RevocationMode.Online,
        RevocationFlag = X509RevocationFlag.EntireChain,
        VerificationFlags = X509VerificationFlags.NoFlag,
        UrlRetrievalTimeout = TimeSpan.FromSeconds(10)
    };

    bool isValid = chain.Build(cert);

    if (!isValid)
    {
        foreach (var status in chain.ChainStatus)
        {
            if (status.Status == X509ChainStatusFlags.Revoked)
            {
                return false;
            }
        }
    }

    return isValid;
}

builder.Services.AddAuthorization();
#endregion

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();
