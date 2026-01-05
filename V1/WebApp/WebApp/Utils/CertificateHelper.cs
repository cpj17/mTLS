using System;
using System.Drawing;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace WebApp.Utils
{
    public static class CertificateHelper
    {
        public static X509Certificate2 GetClientCertificate()
        {
            // Read Base64 from text file (mock AWS Secret)
            string base64 = File.ReadAllText(
                System.Web.HttpContext.Current.Server.MapPath("~/App_Data/clientCertBase64.txt")
            );

            byte[] certBytes = Convert.FromBase64String(base64);

            return new X509Certificate2(
                certBytes,
                "123",
                X509KeyStorageFlags.MachineKeySet |
                X509KeyStorageFlags.PersistKeySet |
                X509KeyStorageFlags.Exportable
            );
        }
    }
}


#region AWS
//using Amazon.SecretsManager;
//using Amazon.SecretsManager.Model;
//using System;
//using System.Security.Cryptography.X509Certificates;
//using System.Text.Json;
//using System.Threading.Tasks;

//public static class CertificateHelper
//{
//    public static async Task<X509Certificate2> GetClientCertificateFromAwsAsync(
//        string secretName,
//        string region,
//        string pfxPassword)
//    {
//        using var client = new AmazonSecretsManagerClient(
//            Amazon.RegionEndpoint.GetBySystemName(region));

//        var request = new GetSecretValueRequest
//        {
//            SecretId = secretName
//        };

//        var response = await client.GetSecretValueAsync(request);

//        if (string.IsNullOrEmpty(response.SecretString))
//            throw new Exception("AWS secret is empty");

//        // If secret is stored as plain Base64 string
//        string base64Cert = response.SecretString;

//        // If secret is JSON like { "cert": "base64..." }
//        // var json = JsonDocument.Parse(response.SecretString);
//        // string base64Cert = json.RootElement.GetProperty("cert").GetString();

//        byte[] certBytes = Convert.FromBase64String(base64Cert);

//        return new X509Certificate2(
//            certBytes,
//            pfxPassword,
//            X509KeyStorageFlags.MachineKeySet |
//            X509KeyStorageFlags.PersistKeySet |
//            X509KeyStorageFlags.Exportable
//        );
//    }
//}
#endregion