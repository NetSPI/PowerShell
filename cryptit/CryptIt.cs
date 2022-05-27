using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Collections.Generic;

// -------------------------------------------------------------------------
// Instructions for compiling DLL and using via PowerShell on the fly
// -------------------------------------------------------------------------
// C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.Runtime.InteropServices.dll /target:library /out:CryptIt.dll CryptIt.cs
// Examples of Calling Functions from PowerShell
// [System.Reflection.Assembly]::LoadFile("C:\temp\CryptIt.dll")
// [CryptIt.EncryptionFunctions]::EncryptStringAES("Encrypt this!","MyPassword")
// EAAAAO/kwWaRfvX6MtvpNx/5HkJg4tqB2AZhs34IKkJUvJzU
// [CryptIt.EncryptionFunctions]::DecryptStringAES("EAAAAO/kwWaRfvX6MtvpNx/5HkJg4tqB2AZhs34IKkJUvJzU","MyPassword")
// Encrypt this!
// $Runner = [CryptIt.EncryptionFunctions]::new()
// $Runner.CryptFilesRecusive("c:\\temp\\enc","MyPassword123",".enc","Yes",10,"1")
// $Runner.CryptFilesRecusive("c:\\temp\\enc","MyPassword123",".enc","No",10,"0")
// $Runner = [CryptIt.EncryptionFunctions]::new()
// $Runner.Main()
// -------------------------------------------------------------------------

namespace CryptIt
{
    public class EncryptionFunctions
    {
        //-------------------------------------------------------------------	
        // STATIC SALT FOR DATA ENCRYPT/DECRYPT
        //-------------------------------------------------------------------
        public static byte[] _salt = Encoding.Unicode.GetBytes("CaptainSalty");

        //-------------------------------------------------------------------	
        // FUNCTION: DATA ENCRYPTION
        //-------------------------------------------------------------------				
        public static string EncryptStringAES(string plainText, string sharedSecret)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException("plainText");
            if (string.IsNullOrEmpty(sharedSecret))
                throw new ArgumentNullException("sharedSecret");

            string outStr = null;                       // Encrypted string to return
            RijndaelManaged aesAlg = null;              // RijndaelManaged object used to encrypt the data.

            try
            {
                // generate the key from the shared secret and the salt
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(sharedSecret, _salt);

                // Create a RijndaelManaged object
                aesAlg = new RijndaelManaged();
                aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                aesAlg.Mode = CipherMode.ECB;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    // prepend the IV
                    msEncrypt.Write(BitConverter.GetBytes(aesAlg.IV.Length), 0, sizeof(int));
                    msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                    }
                    outStr = Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
            finally
            {
                // Clear the RijndaelManaged object.
                if (aesAlg != null)
                    aesAlg.Clear();
            }

            // Return the encrypted bytes from the memory stream.		
            return outStr;
        }
        //-------------------------------------------------------------------	
        // FUNCTION: DATA DECRYPTION
        //-------------------------------------------------------------------	
        public static string DecryptStringAES(string cipherText, string sharedSecret)
        {
            if (string.IsNullOrEmpty(cipherText))
                throw new ArgumentNullException("cipherText");
            if (string.IsNullOrEmpty(sharedSecret))
                throw new ArgumentNullException("sharedSecret");

            // Declare the RijndaelManaged object
            // used to decrypt the data.
            RijndaelManaged aesAlg = null;

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            try
            {
                // generate the key from the shared secret and the salt
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(sharedSecret, _salt);

                // Create the streams used for decryption.                
                byte[] bytes = Convert.FromBase64String(cipherText);
                using (MemoryStream msDecrypt = new MemoryStream(bytes))
                {
                    // Create a RijndaelManaged object
                    // with the specified key and IV.
                    aesAlg = new RijndaelManaged();
                    aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                    aesAlg.Mode = CipherMode.ECB;

                    // Get the initialization vector from the encrypted stream
                    aesAlg.IV = ReadByteArray(msDecrypt);
                    // Create a decrytor to perform the stream transform.
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
            finally
            {
                // Clear the RijndaelManaged object.
                if (aesAlg != null)
                    aesAlg.Clear();
            }
            return plaintext;
        }

        private static byte[] ReadByteArray(Stream s)
        {
            byte[] rawLength = new byte[sizeof(int)];
            if (s.Read(rawLength, 0, rawLength.Length) != rawLength.Length)
            {
                throw new SystemException("Stream did not contain properly formatted byte array");
            }

            byte[] buffer = new byte[BitConverter.ToInt32(rawLength, 0)];
            if (s.Read(buffer, 0, buffer.Length) != buffer.Length)
            {
                throw new SystemException("Did not read byte array properly");
            }

            return buffer;
        }


        //-------------------------------------------------------------------
        // FUNCTION: GenerateKeys
        //-------------------------------------------------------------------
        // https://www.sysadmins.lv/retired-msft-blogs/alejacma/how-to-generate-key-pairs-encrypt-and-decrypt-data-with-net-csharp.aspx

        public static void GenerateKeys(string publicKeyFileName, string privateKeyFileName)
        {
            // Variables
            CspParameters cspParams = null;
            RSACryptoServiceProvider rsaProvider = null;
            StreamWriter publicKeyFile = null;
            StreamWriter privateKeyFile = null;
            string publicKey = "";
            string privateKey = "";

            try
            {
                // Create a new key pair on target CSP
                cspParams = new CspParameters();
                cspParams.ProviderType = 1; // PROV_RSA_FULL

                //cspParams.ProviderName; // CSP name
                cspParams.Flags = CspProviderFlags.UseArchivableKey;
                cspParams.KeyNumber = (int)KeyNumber.Exchange;
                rsaProvider = new RSACryptoServiceProvider(cspParams);

                // Export public key
                publicKey = rsaProvider.ToXmlString(false);

                // Write public key to file
                publicKeyFile = File.CreateText(publicKeyFileName);

                publicKeyFile.Write(publicKey);

                // Export private/public key pair
                privateKey = rsaProvider.ToXmlString(true);

                // Write private/public key pair to file
                privateKeyFile = File.CreateText(privateKeyFileName);
                privateKeyFile.Write(privateKey);

            }
            catch (Exception ex)
            {
                // Any errors? Show them
                Console.WriteLine("Exception generating a new key pair! More info:");
                Console.WriteLine(ex.Message);
            }

            finally
            {
                // Do some clean up if needed
                if (publicKeyFile != null)
                {
                    publicKeyFile.Close();
                }

                if (privateKeyFile != null)
                {
                    privateKeyFile.Close();
                }
            }
        } // Keys


        //-------------------------------------------------------------------
        // FUNCTION: ENCRYPT WITH PUBLIC KEY
        //-------------------------------------------------------------------
        // https://www.sysadmins.lv/retired-msft-blogs/alejacma/how-to-generate-key-pairs-encrypt-and-decrypt-data-with-net-csharp.aspx

        public static void EncryptWithKey(string publicKeyFileName, string plainFileName, string encryptedFileName)
        {
            // Variables
            CspParameters cspParams = null;
            RSACryptoServiceProvider rsaProvider = null;
            StreamReader publicKeyFile = null;
            StreamReader plainFile = null;
            FileStream encryptedFile = null;
            string publicKeyText = "";
            string plainText = "";
            byte[] plainBytes = null;
            byte[] encryptedBytes = null;

            try
            {
                // Select target CSP
                cspParams = new CspParameters();
                cspParams.ProviderType = 1; // PROV_RSA_FULL

                //cspParams.ProviderName; // CSP name
                rsaProvider = new RSACryptoServiceProvider(cspParams);

                // Read public key from file
                publicKeyFile = File.OpenText(publicKeyFileName);
                publicKeyText = publicKeyFile.ReadToEnd();

                // Import public key
                rsaProvider.FromXmlString(publicKeyText);

                // Read plain text from file
                plainFile = File.OpenText(plainFileName);
                plainText = plainFile.ReadToEnd();

                // Encrypt plain text
                plainBytes = Encoding.Unicode.GetBytes(plainText);
                encryptedBytes = rsaProvider.Encrypt(plainBytes, false);

                // Write encrypted text to file
                encryptedFile = File.Create(encryptedFileName);
                encryptedFile.Write(encryptedBytes, 0, encryptedBytes.Length);
            }
            catch (Exception ex)
            {
                // Any errors? Show them
                Console.WriteLine("Exception encrypting file! More info:");
                Console.WriteLine(ex.Message);
            }
            finally
            {
                // Do some clean up if needed
                if (publicKeyFile != null)
                {
                    publicKeyFile.Close();
                }

                if (plainFile != null)
                {
                    plainFile.Close();
                }

                if (encryptedFile != null)
                {
                    encryptedFile.Close();
                }
            }


        } // Encrypt


        //-------------------------------------------------------------------
        // FUNCTION: DECRYPT WITH PRIVATE KEY
        //-------------------------------------------------------------------
        // https://www.sysadmins.lv/retired-msft-blogs/alejacma/how-to-generate-key-pairs-encrypt-and-decrypt-data-with-net-csharp.aspx

        public static void DecryptWithKey(string privateKeyFileName, string encryptedFileName, string plainFileName)
        {
            // Variables
            CspParameters cspParams = null;
            RSACryptoServiceProvider rsaProvider = null;
            StreamReader privateKeyFile = null;
            FileStream encryptedFile = null;
            StreamWriter plainFile = null;
            string privateKeyText = "";
            string plainText = "";
            byte[] encryptedBytes = null;
            byte[] plainBytes = null;

            try
            {
                // Select target CSP
                cspParams = new CspParameters();
                cspParams.ProviderType = 1; // PROV_RSA_FULL

                //cspParams.ProviderName; // CSP name
                rsaProvider = new RSACryptoServiceProvider(cspParams);

                // Read private/public key pair from file
                privateKeyFile = File.OpenText(privateKeyFileName);
                privateKeyText = privateKeyFile.ReadToEnd();

                // Import private/public key pair
                rsaProvider.FromXmlString(privateKeyText);

                // Read encrypted text from file
                encryptedFile = File.OpenRead(encryptedFileName);
                encryptedBytes = new byte[encryptedFile.Length];
                encryptedFile.Read(encryptedBytes, 0, (int)encryptedFile.Length);

                // Decrypt text
                plainBytes = rsaProvider.Decrypt(encryptedBytes, false);

                // Write decrypted text to file
                plainFile = File.CreateText(plainFileName);
                plainText = Encoding.Unicode.GetString(plainBytes);
                plainFile.Write(plainText);
            }
            catch (Exception ex)
            {
                // Any errors? Show them
                Console.WriteLine("Exception decrypting file! More info:");
                Console.WriteLine(ex.Message);
            }
            finally
            {
                // Do some clean up if needed
                if (privateKeyFile != null)
                {
                    privateKeyFile.Close();
                }

                if (encryptedFile != null)
                {
                    encryptedFile.Close();
                }

                if (plainFile != null)
                {
                    plainFile.Close();
                }
            }
        } // Decrypt


        //-------------------------------------------------------------------
        // Recursive Directory Listing
        //-------------------------------------------------------------------
        // https://stackoverflow.com/questions/929276/how-to-recursively-list-all-the-files-in-a-directory-in-c

        static IEnumerable<string> GetFiles(string path)
        {
            Queue<string> queue = new Queue<string>();
            queue.Enqueue(path);
            while (queue.Count > 0)
            {
                path = queue.Dequeue();
                try
                {
                    foreach (string subDir in Directory.GetDirectories(path))
                    {
                        queue.Enqueue(subDir);
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(ex);
                }
                string[] files = null;
                try
                {
                    files = Directory.GetFiles(path);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(ex);
                }
                if (files != null)
                {
                    for (int i = 0; i < files.Length; i++)
                    {
                        yield return files[i];
                    }
                }
            }
        }


        //-------------------------------------------------------------------
        // DYNAMIC SALT FOR AES FILE ENCRYPTION
        //-------------------------------------------------------------------
        // https://ourcodeworld.com/articles/read/471/how-to-encrypt-and-decrypt-files-using-the-aes-encryption-algorithm-in-c-sharp

        public static byte[] GenerateRandomSalt()
        {
            byte[] data = new byte[32];

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                for (int i = 0; i < 10; i++)
                {
                    // Fille the buffer with the generated data
                    rng.GetBytes(data);
                }
            }

            return data;
        }

        //-------------------------------------------------------------------
        // FUNCTION: ENCRYPT FILE WITH AES PASSWORD
        //-------------------------------------------------------------------
        // https://ourcodeworld.com/articles/read/471/how-to-encrypt-and-decrypt-files-using-the-aes-encryption-algorithm-in-c-sharp

        public static void FileEncrypt(string inputFile, string password, string fileExt)
        {
            //http://stackoverflow.com/questions/27645527/aes-encryption-on-large-files

            //generate random salt
            byte[] salt = GenerateRandomSalt();

            //create output file name
            FileStream fsCrypt = new FileStream(inputFile + fileExt, FileMode.Create);

            //convert password string to byte arrray
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

            //Set Rijndael symmetric encryption algorithm
            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            AES.Padding = PaddingMode.PKCS7;

            //http://stackoverflow.com/questions/2659214/why-do-i-need-to-use-the-rfc2898derivebytes-class-in-net-instead-of-directly
            //"What it does is repeatedly hash the user password along with the salt." High iteration counts.
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);

            //Cipher modes: http://security.stackexchange.com/questions/52665/which-is-the-best-cipher-mode-and-padding-mode-for-aes-encryption
            AES.Mode = CipherMode.CFB;

            // write salt to the begining of the output file, so in this case can be random every time
            fsCrypt.Write(salt, 0, salt.Length);

            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateEncryptor(), CryptoStreamMode.Write);

            FileStream fsIn = new FileStream(inputFile, FileMode.Open);

            //create a buffer (1mb) so only this amount will allocate in the memory and not the whole file
            byte[] buffer = new byte[1048576];
            int read;

            try
            {
                while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cs.Write(buffer, 0, read);
                }

                // Close up
                fsIn.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
            finally
            {
                cs.Close();
                fsCrypt.Close();
            }
        }


        //-------------------------------------------------------------------
        // FUNCTION: DECRYPT FILE WITH AES PASSWORD
        //-------------------------------------------------------------------
        // https://ourcodeworld.com/articles/read/471/how-to-encrypt-and-decrypt-files-using-the-aes-encryption-algorithm-in-c-sharp

        public static void FileDecrypt(string inputFile, string outputFile, string password)
        {
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] salt = new byte[32];

            FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);
            fsCrypt.Read(salt, 0, salt.Length);

            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);
            AES.Padding = PaddingMode.PKCS7;
            AES.Mode = CipherMode.CFB;

            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateDecryptor(), CryptoStreamMode.Read);

            FileStream fsOut = new FileStream(outputFile, FileMode.Create);

            int read;
            byte[] buffer = new byte[1048576];

            try
            {
                while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    fsOut.Write(buffer, 0, read);
                }
            }
            catch (CryptographicException ex_CryptographicException)
            {
                Console.WriteLine("CryptographicException error: " + ex_CryptographicException.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }

            try
            {
                cs.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error by closing CryptoStream: " + ex.Message);
            }
            finally
            {
                fsOut.Close();
                fsCrypt.Close();
            }
        }

        //-------------------------------------------------------------------
        // FUNCTION: ENCRYPT/DECRYPT FILES RECURISVELY WITH AES PASSWORD
        //-------------------------------------------------------------------        
        public static void DirFileEncryptRec1(string targetFilepath, string aesPassword, string fileExt, string genFiles, int Filenumb, string cryptMode)
        {

            // Add check for all parameters

            // Set AES encryoption password
            string mypassword = aesPassword;
            Console.WriteLine("AES Encryption Password: {0}", mypassword);

            // Set file path
            string myfilepath = targetFilepath;
            Console.WriteLine("Target Directory: {0}", myfilepath);

            // Set crypto mode
            //string cryptmode = "0"; // 0=decryption 1=encryption

            // Set file generation settings
            string enableFileGen = genFiles; //yes or no
            int genFilenum = Filenumb; //default to 1000

            // Generating testing files    
            if (enableFileGen == "Yes")
            {
                Console.WriteLine("Generating {0} test files in directory", genFilenum);
                for (int i = 0; i < genFilenum; i++)
                {
                    //Console.WriteLine("ITERATION: {0}", i);
                    string path = targetFilepath + "\\file" + i + ".txt";
                    // Create the file, or overwrite if the file exists.
                    using (FileStream fs = File.Create(path))
                    {
                        byte[] info = new System.Text.UTF8Encoding(true).GetBytes("This is some text in the file.");
                        // Add some information to the file.
                        fs.Write(info, 0, info.Length);
                        // Console.WriteLine("- Creating: {0}",path);
                    }
                }
            }

            // Search through taret directory recurisvely and encrypt files	
            if (cryptMode == "1")
            {
                Console.WriteLine("Encrypting files...");
            }
            else
            {
                Console.WriteLine("Decrypting files...");
            }

            foreach (string file in GetFiles(myfilepath))
            {

                // Encrypt files
                if (cryptMode == "1")
                {
                    // Encrypt file
                    //Console.WriteLine("Encrypting {0}",file);
                    FileEncrypt(file, aesPassword, fileExt);

                    // Remove original file
                    // Console.WriteLine("Removing {0}",file);
                    File.Delete(file);
                }

                // Decrypt files
                if (cryptMode == "0")
                {
                    // Decrypt file		
                    string newfilePath = file + ".decrypted.txt";
                    Console.WriteLine("Decrypting {0} to {1}", file, newfilePath);
                    FileDecrypt(file, newfilePath, aesPassword);
                    File.Delete(file);
                }
            }

            Console.WriteLine("Operation complete.");
        }

        //-------------------------------------------------------------------
        // FUNCTION: ENCRYPT/DECRYPT FILES RECURISVELY WITH AES PASSWORD 2 - FASTER
        //------------------------------------------------------------------- 
        public static void DirFileEncryptRec2(string targetDirectory, string aesPassword, string fileExt, string genFiles, int genFilenum, string cryptMode)
        {

            // ----------------------------------------------------
            // Generate sample files 
            // ---------------------------------------------------
            if (genFiles == "Yes")
            {
                Console.WriteLine("Generating {0} test files in directory", genFilenum);
                for (int i = 0; i < genFilenum; i++)
                {
                    //Console.WriteLine("ITERATION: {0}", i);
                    string path = targetDirectory + "\\file" + i + ".txt";
                    // Create the file, or overwrite if the file exists.
                    using (FileStream fs = File.Create(path))
                    {
                        byte[] info = new System.Text.UTF8Encoding(true).GetBytes("This is some text in the file.");
                        // Add some information to the file.
                        fs.Write(info, 0, info.Length);
                        // Console.WriteLine("- Creating: {0}",path);
                    }
                }
            }

            // ----------------------------------------------------
            // Setup Encryption
            // ----------------------------------------------------
            //http://stackoverflow.com/questions/27645527/aes-encryption-on-large-files		

            // Generate random salt
            // byte[] salt = GenerateRandomSalt();
            byte[] salt = Encoding.Unicode.GetBytes("CaptainSalty");

            // Convert password string to byte arrray
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(aesPassword);

            //Set Rijndael symmetric encryption algorithm
            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            AES.Padding = PaddingMode.PKCS7;

            // http://stackoverflow.com/questions/2659214/why-do-i-need-to-use-the-rfc2898derivebytes-class-in-net-instead-of-directly
            // "What it does is repeatedly hash the user password along with the salt." High iteration counts.
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);

            //Cipher modes: http://security.stackexchange.com/questions/52665/which-is-the-best-cipher-mode-and-padding-mode-for-aes-encryption
            AES.Mode = CipherMode.CFB;

            // Encrypt files
            if (cryptMode == "1")
            {
                Console.WriteLine("Encrypting all files in: {0}", targetDirectory);
                // ----------------------------------------------------
                // Loop through files in target directory
                //----------------------------------------------------
                foreach (string file in GetFiles(targetDirectory))
                {

                    // LOOP START
                    // Create a new file for the encrypted data
                    FileStream fsCrypt = new FileStream(file + fileExt, FileMode.Create);

                    // Write salt to the begining of the new file
                    fsCrypt.Write(salt, 0, salt.Length);

                    // Create a cyptostream to encrypt the data written to the new file
                    CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateEncryptor(), CryptoStreamMode.Write);

                    // Open the new file for the encrypted data
                    FileStream fsIn = new FileStream(file, FileMode.Open);

                    // Create a buffer (1mb) so only this amount will allocate in the memory and not the whole file
                    byte[] buffer = new byte[1048576];
                    int read;

                    // Encrypt the file 
                    try
                    {
                        while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            cs.Write(buffer, 0, read);
                        }

                        // Close up
                        fsIn.Close();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Error: " + ex.Message);
                    }
                    finally
                    {
                        cs.Close();
                        fsCrypt.Close();
                        File.Delete(file);
                    }
                    // LOOOP END
                }

                Console.WriteLine("Operation complete.");
            }

            // Decrypt files
            if (cryptMode == "0")
            {
                Console.WriteLine("Decrypting all files in: {0}", targetDirectory);

                foreach (string file in GetFiles(targetDirectory))
                {
                    // Create new decrypted file name
                    // string myPath = "test.txt";
                    // var myFile = myPath.ToFileInfo();
                    string decfilePath = file + ".decrypted.txt";                    

                    // Open encrypted file
                    FileStream fsCrypt = new FileStream(file, FileMode.Open);

                    // Read the salt from the beginning of the file
                    fsCrypt.Read(salt, 0, salt.Length);

                    // Create strem to decrypt data from source file
                    CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateDecryptor(), CryptoStreamMode.Read);

                    // Create new decrypted file
                    FileStream fsOut = new FileStream(decfilePath, FileMode.Create);

                    int read;
                    byte[] buffer = new byte[1048576];

                    try
                    {
                        while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            fsOut.Write(buffer, 0, read);
                        }
                    }
                    catch (CryptographicException ex_CryptographicException)
                    {
                        Console.WriteLine("CryptographicException error: " + ex_CryptographicException.Message);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Error: " + ex.Message);
                    }

                    try
                    {
                        cs.Close();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Error by closing CryptoStream: " + ex.Message);
                    }
                    finally
                    {
                        fsOut.Close();
                        fsCrypt.Close();
                        File.Delete(file);
                    }
                }
            }
        }
    }
}
