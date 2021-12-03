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
using System.IO;
using System.Text;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using NUnit.Framework;

namespace Net.Pkcs11Interop.PkiUtils.Tests
{
    /// <summary>
    /// Tests for Net.Pkcs11Interop.PkiUtils.CertificateRequest class
    /// </summary>
    [TestFixture()]
    public class CertificateRequestTest
    {
        /// <summary>
        /// PKCS#10 certificate request generation test
        /// </summary>
        [Test()]
        public static void GeneratePkcs10Test()
        {
            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, false))
            {
                // Find usable slot
                Slot slot = Helpers.FindSlot(pkcs11, Settings.TokenSerial, Settings.TokenLabel);
                Assert.IsNotNull(slot);

                // Open RW session
                using (Session session = slot.OpenSession(false))
                {
                    // Login as normal user
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Choose unique values for CKA_LABEL and CKA_ID attributes
                    string ckaLabel = Guid.NewGuid().ToString();
                    byte[] ckaId = session.GenerateRandom(20);

                    // Generate key pair
                    ObjectHandle publicKeyHandle = null;
                    ObjectHandle privateKeyHandle = null;
                    Helpers.GenerateKeyPair(session, ckaLabel, ckaId, out publicKeyHandle, out privateKeyHandle);

                    // Generate certificate request in PKCS#10 format
                    string subjectDistinguishedName = @"OU=IT,O=Cong Ty Co Phan Chu Ky So Vi Na,L=Ho Chi Minh,CN=smartsign.com.vn,C=VN";
                    byte[] pkcs10 = CertificateRequest.GeneratePkcs10(session, publicKeyHandle, privateKeyHandle, subjectDistinguishedName, HashAlgorithm.SHA256);

                    // Do something interesting with certificate request
                    // write csr to file
                    ByteArrayToFile("smartcard.csr", pkcs10);

                    StringBuilder builder = new StringBuilder();
                    builder.AppendLine("-----BEGIN NEW CERTIFICATE REQUEST-----");
                    builder.AppendLine(Convert.ToBase64String(pkcs10, Base64FormattingOptions.InsertLineBreaks));
                    builder.AppendLine("-----END NEW CERTIFICATE REQUEST-----");
                    Console.WriteLine(builder.ToString());
                    File.WriteAllText("smartcard.pem", builder.ToString());
                    // Destroy keys
                    session.DestroyObject(privateKeyHandle);
                    session.DestroyObject(publicKeyHandle);

                    session.Logout();
                }
            }
        }

        public static bool ByteArrayToFile(string fileName, byte[] byteArray)
        {
            try
            {
                using (var fs = new FileStream(fileName, FileMode.Create, FileAccess.Write))
                {
                    fs.Write(byteArray, 0, byteArray.Length);
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception caught in process: {0}", ex);
                return false;
            }
        }
    }
}

