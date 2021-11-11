using System;
using System.Collections.Generic;
using System.Linq;

namespace NewCertificateGenerator
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var certificateGenerator  = new CertificateGenerator();
            certificateGenerator.Work();
        }

        
    }
}