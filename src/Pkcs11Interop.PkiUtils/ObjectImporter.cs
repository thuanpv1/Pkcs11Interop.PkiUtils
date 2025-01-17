/*
 *  Pkcs11Interop.PkiUtils - PKI extensions for Pkcs11Interop library
 *  Copyright (c) 2013-2014 JWC s.r.o. <http://www.jwc.sk>
 *  Author: Jaroslav Imrich <jimrich@jimrich.sk>
 *
 *  Licensing for open source projects:
 *  Pkcs11Interop.PkiUtils is available under the terms of the GNU Affero General 
 *  Public License version 3 as published by the Free Software Foundation.
 *  Please see <http://www.gnu.org/licenses/agpl-3.0.html> for more details.
 *
 *  Licensing for other types of projects:
 *  Pkcs11Interop.PkiUtils is available under the terms of flexible commercial license.
 *  Please contact JWC s.r.o. at <info@pkcs11interop.net> for more details.
 */

using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;

namespace Net.Pkcs11Interop.PkiUtils
{
    /// <summary>
    /// Utilities for object importing
    /// </summary>/summary>
    public static class ObjectImporter
    {
        /// <summary>
        /// Imports the certificate into the PKCS#11 compatible device and pairs it with the corresponding private key
        /// </summary>
        /// <param name="session">Session with user logged in</param>
        /// <param name="certificate">Certificate that should be imported</param>
        /// <returns>Handle of created certificate object</returns>
        public static ObjectHandle ImportCertificate(Session session, byte[] certificate)
        {
            // Parse certificate
            X509CertificateParser x509CertificateParser = new X509CertificateParser();
            X509Certificate x509Certificate = x509CertificateParser.ReadCertificate(certificate);

            // Get public key from certificate
            AsymmetricKeyParameter pubKeyParams = x509Certificate.GetPublicKey();
            if (!(pubKeyParams is RsaKeyParameters))
                throw new NotSupportedException("Currently only RSA keys are supported");
            RsaKeyParameters rsaPubKeyParams = (RsaKeyParameters)pubKeyParams;

            // Find corresponding private key
            List<ObjectAttribute> privKeySearchTemplate = new List<ObjectAttribute>();
            privKeySearchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            privKeySearchTemplate.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA));
            privKeySearchTemplate.Add(new ObjectAttribute(CKA.CKA_MODULUS, rsaPubKeyParams.Modulus.ToByteArrayUnsigned()));
            privKeySearchTemplate.Add(new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, rsaPubKeyParams.Exponent.ToByteArrayUnsigned()));

            List<ObjectHandle> foundObjects = session.FindAllObjects(privKeySearchTemplate);
            if (foundObjects.Count != 1)
                throw new ObjectNotFoundException("Corresponding RSA private key not found");

            ObjectHandle privKeyObjectHandle = foundObjects[0];

            // Read CKA_LABEL and CKA_ID attributes of private key
            List<CKA> privKeyAttrsToRead = new List<CKA>();
            privKeyAttrsToRead.Add(CKA.CKA_LABEL);
            privKeyAttrsToRead.Add(CKA.CKA_ID);

            List<ObjectAttribute> privKeyAttributes = session.GetAttributeValue(privKeyObjectHandle, privKeyAttrsToRead);

            // Define attributes of new certificate object
            List<ObjectAttribute> certificateAttributes = new List<ObjectAttribute>();
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, false));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_MODIFIABLE, true));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, privKeyAttributes[0].GetValueAsString()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_TRUSTED, false));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_SUBJECT, x509Certificate.SubjectDN.GetDerEncoded()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_ID, privKeyAttributes[1].GetValueAsByteArray()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_ISSUER, x509Certificate.IssuerDN.GetDerEncoded()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_SERIAL_NUMBER, new DerInteger(x509Certificate.SerialNumber).GetDerEncoded()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_VALUE, x509Certificate.GetEncoded()));

            // Create certificate object
            return session.CreateObject(certificateAttributes);
        }

        /// <summary>
        /// Imports trusted certificate into the PKCS#11 compatible device
        /// </summary>
        /// <param name="session">Session with user logged in</param>
        /// <param name="certificate">Certificate that should be imported</param>
        /// <returns>Handle of created certificate object</returns>
        public static ObjectHandle ImportTrustedCertificate(Session session, byte[] certificate)
        {
            // Choose unique values for CKA_LABEL and CKA_ID attributes
            string ckaLabel = Guid.NewGuid().ToString();
            byte[] ckaId = session.GenerateRandom(20);

            return ImportTrustedCertificate(session, certificate, ckaLabel, ckaId);
        }

        /// <summary>
        /// Imports trusted certificate into the PKCS#11 compatible device
        /// </summary>
        /// <param name="session">Session with user logged in</param>
        /// <param name="certificate">Certificate that should be imported</param>
        /// <param name="ckaLabel">Value of CKA_LABEL attribute</param>
        /// <param name="ckaId">Value of CKA_ID attribute</param>
        /// <returns>Handle of created certificate object</returns>
        public static ObjectHandle ImportTrustedCertificate(Session session, byte[] certificate, string ckaLabel, byte[] ckaId)
        {
            // Parse certificate
            X509CertificateParser x509CertificateParser = new X509CertificateParser();
            X509Certificate x509Certificate = x509CertificateParser.ReadCertificate(certificate);

            // Define attributes of new certificate object
            List<ObjectAttribute> certificateAttributes = new List<ObjectAttribute>();
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, false));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_MODIFIABLE, true));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, ckaLabel));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_TRUSTED, true));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_SUBJECT, x509Certificate.SubjectDN.GetDerEncoded()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_ISSUER, x509Certificate.IssuerDN.GetDerEncoded()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_SERIAL_NUMBER, new DerInteger(x509Certificate.SerialNumber).GetDerEncoded()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_VALUE, x509Certificate.GetEncoded()));

            // Create certificate object
            return session.CreateObject(certificateAttributes);
        }
    }
}
