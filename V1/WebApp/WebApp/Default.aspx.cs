using System;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using WebApp.Models;
using WebApp.Utils;

namespace WebApp
{
    public partial class Default : System.Web.UI.Page
    {
        protected async void btnCallApi_Click(object sender, EventArgs e)
        {
            // Bind UI to request object
            clsRequest request = new clsRequest
            {
                UserName = txtUserName.Text,
                Password = txtPassword.Text
            };

            // Load client certificate
            X509Certificate2 clientCert = CertificateHelper.GetClientCertificate();

            // Attach certificate to handler (mTLS)
            HttpClientHandler handler = new HttpClientHandler();
            handler.ClientCertificates.Add(clientCert);

            using (HttpClient client = new HttpClient(handler))
            {
                client.BaseAddress = new Uri("https://your-api-url");

                string json = JsonSerializer.Serialize(request);
                HttpContent content = new StringContent(json, Encoding.UTF8, "application/json");

                HttpResponseMessage response = await client.PostAsync("https://localhost:7262/api/auth/login", content);

                lblResult.Text = response.IsSuccessStatusCode
                    ? "API Call Successful"
                    : "API Call Failed";

                lblResult.Text = response.Content.ReadAsStringAsync().Result;

                lblResult.Text = lblResult.Text.Length == 0 ? response.IsSuccessStatusCode
                    ? "API Call Successful"
                    : "API Call Failed"

                    : lblResult.Text;
            }
        }
    }
}
