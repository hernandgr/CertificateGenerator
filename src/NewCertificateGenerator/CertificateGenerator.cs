using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace NewCertificateGenerator
{
    public class CertificateGenerator
    {
        public void Work()
        {
            var signingCert = GenerateRootCert();
            
            GenerateClientCert(signingCert);
        }

        private X509Certificate2 GenerateRootCert()
        {
            var rootCertName = "GRPC_ROOT_CERT";

            using var rsa = RSA.Create(2048); // 1024, 2048 or 4096
            var request = new CertificateRequest(
                $"CN={rootCertName}",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);


            request.CertificateExtensions.Add(
               new X509BasicConstraintsExtension(
                   true,
                   true,
                   3,
                   true));

            var x509KeyUsageFlags = X509KeyUsageFlags.KeyCertSign;
            request.CertificateExtensions.Add(new X509KeyUsageExtension(x509KeyUsageFlags, true));

            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddDnsName("localhost");
            request.CertificateExtensions.Add(sanBuilder.Build());

            var enhancedKeyUsages = new OidCollection {
                new Oid("1.3.6.1.5.5.7.3.2"), // ClientAuthentication,
                new Oid("1.3.6.1.5.5.7.3.1"), // ServerAuthentication
            };

            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(enhancedKeyUsages, false));

            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

            var notbefore = DateTimeOffset.UtcNow.AddHours(-2);
            var notafter = DateTimeOffset.UtcNow.AddYears(10);

            X509Certificate2 generatedCertificate = request.CreateSelfSigned(notbefore, notafter);

            var bytes = CertificateToPfx("1234", generatedCertificate, null, null);
            File.WriteAllBytes(@$"C:\Cert\${rootCertName}.pfx", bytes);

            return generatedCertificate;
        }

        private void GenerateClientCert(X509Certificate2 signingCertificate)
        {
            if (signingCertificate == null)
            {
                throw new ArgumentNullException(nameof(signingCertificate));
            }

            if (!signingCertificate.HasPrivateKey)
            {
                throw new Exception("Signing cert must have private key");
            }

            var clientCertName = "GRPC_CLIENT_CERT";

            using var rsa = RSA.Create(2048); // 1024, 2048 or 4096
            var request = new CertificateRequest(
                $"CN={clientCertName}",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            request.CertificateExtensions.Add(
               new X509BasicConstraintsExtension(
                   false,
                   false,
                   0,
                   false));

            var x509KeyUsageFlags = X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment;
            request.CertificateExtensions.Add(new X509KeyUsageExtension(x509KeyUsageFlags, true));


            // set the AuthorityKeyIdentifier. There is no built-in 
            // support, so it needs to be copied from the Subject Key 
            // Identifier of the signing certificate and massaged slightly.
            // AuthorityKeyIdentifier is "KeyID=<subject key identifier>"
            foreach (var item in signingCertificate.Extensions)
            {
                if (item.Oid.Value == "2.5.29.14") //  "Subject Key Identifier"
                {
                    var issuerSubjectKey = item.RawData;
                    //var issuerSubjectKey = signingCertificate.Extensions["Subject Key Identifier"].RawData;
                    var segment = new ArraySegment<byte>(issuerSubjectKey, 2, issuerSubjectKey.Length - 2);
                    var authorityKeyIdentifier = new byte[segment.Count + 4];
                    // "KeyID" bytes
                    authorityKeyIdentifier[0] = 0x30;
                    authorityKeyIdentifier[1] = 0x16;
                    authorityKeyIdentifier[2] = 0x80;
                    authorityKeyIdentifier[3] = 0x14;
                    segment.CopyTo(authorityKeyIdentifier, 4);
                    request.CertificateExtensions.Add(new X509Extension("2.5.29.35", authorityKeyIdentifier, false));
                    break;
                }
            }

            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddDnsName("localhost");
            request.CertificateExtensions.Add(sanBuilder.Build());

            var enhancedKeyUsages = new OidCollection {
                new Oid("1.3.6.1.5.5.7.3.2"), // ClientAuthentication,
                //new Oid("1.3.6.1.5.5.7.3.1"), // ServerAuthentication
            };

            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(enhancedKeyUsages, false));

            // add this subject key identifier
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

            var notbefore = DateTimeOffset.UtcNow.AddHours(-1);
            var notafter = DateTimeOffset.UtcNow.AddYears(1);

            // cert serial is the epoch/unix timestamp
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var unixTime = Convert.ToInt64((DateTime.UtcNow - epoch).TotalSeconds);
            var serial = BitConverter.GetBytes(unixTime);
            var cert = request.Create(
                            signingCertificate,
                            notbefore,
                            notafter,
                            serial);

            var cert2 = cert.CopyWithPrivateKey(rsa);

            var clientCertL3InPfxBtyes = ExportChainedCertificatePfx("1234", cert2, signingCertificate);
            File.WriteAllBytes(@$"C:\Cert\{clientCertName}.pfx", clientCertL3InPfxBtyes);
            //AddToStore(cert2, StoreName.My, StoreLocation.LocalMachine);
        }

        private void AddToStore(X509Certificate2 cert, StoreName storeName, StoreLocation storeLocation)
        {
            using var store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);

            // Remove existing certificates.
            var existingCerts = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, cert.Subject, false);
            if (existingCerts.Count > 0)
            {
                //_logger.LogInformation($"Found {existingCerts.Count} existing certificates to remove in store");

                store.RemoveRange(existingCerts);
            }

            // Add new certificates.
            store.Add(cert);
            store.Close();
        }

        public byte[] ExportChainedCertificatePfx(string password, X509Certificate2 certificate, X509Certificate2 signingCert)
        {
            var caCertCollection = GetCertificateCollection(signingCert, password);
            var publicKeySigningCert = ExportCertificatePublicKey(signingCert);
            return CertificateToPfx(password, certificate, publicKeySigningCert, caCertCollection);
        }

        private byte[] CertificateToPfx(string password,
            X509Certificate2 certificate,
            X509Certificate2 signingCertificate,
            X509Certificate2Collection chain)
        {
            var certCollection = new X509Certificate2Collection(certificate);
            if (chain != null)
            {
                certCollection.AddRange(chain);
            }

            if (signingCertificate != null)
            {
                var signingCertWithoutPrivateKey = ExportCertificatePublicKey(signingCertificate);
                certCollection.Add(signingCertWithoutPrivateKey);
            }

            return certCollection.Export(X509ContentType.Pkcs12, password);
        }

        private X509Certificate2Collection GetCertificateCollection(X509Certificate2 inputCert, string password)
        {
            var certificateCollection = new X509Certificate2Collection();
            certificateCollection.Import(inputCert.GetRawCertData(), password,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet);

            X509Certificate2 certificate = null;
            var outcollection = new X509Certificate2Collection();
            foreach (X509Certificate2 element in certificateCollection)
            {
                if (certificate == null && element.HasPrivateKey)
                {
                    certificate = element;
                }
                else
                {
                    outcollection.Add(element);
                }
            }

            if (certificate == null)
            {
                return null;
            }
            else
            {
                return outcollection;
            }
        }

        public X509Certificate2 ExportCertificatePublicKey(X509Certificate2 certificate)
        {
            var publicKeyBytes = certificate.Export(X509ContentType.Cert);
            var signingCertWithoutPrivateKey = new X509Certificate2(publicKeyBytes);
            return signingCertWithoutPrivateKey;
        }
    }
}
