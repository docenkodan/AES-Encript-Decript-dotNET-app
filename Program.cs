using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography;

namespace AES1
{
    class Program
    {
        static void Main(string[] args)
        {
            string command = "y";
            while (command == "y")
            {
                StartCryption SC = new StartCryption();

                Console.WriteLine("Выберете режим работы. (e - шифрование, d - дешифрование)");
                command = Console.ReadLine();
                if (command == "e")
                {
                    SC.StartEncrypt();
                }
                else if (command == "d")
                {
                    SC.StartDecrypt();
                }

                Console.WriteLine("Продолжить работу с приложением? (y - да, n - нет)");
                command = Console.ReadLine();
            }
        }

        public sealed class StartCryption
        {
            private string data;
            private string secretKey;
            private string initVector;
            private string cipherMode;

            public void ReadParams(string operatingMode)
            {
                if (operatingMode == "encrypt")
                {
                    Console.WriteLine("Введите схему шифрования: (ECB, CBC, OFB, CFB, CTS)");
                    cipherMode = Console.ReadLine();
                    Console.WriteLine("Введите шифруемую строку: ");
                    data = Console.ReadLine();
                }
                else if (operatingMode == "decrypt")
                {
                    Console.WriteLine("Введите схему дешифрования: (ECB, CBC, OFB, CFB, CTS)");
                    cipherMode = Console.ReadLine();
                    Console.WriteLine("Введите зашифрованную строку в формате base64: ");
                    data = Console.ReadLine();
                }
                Console.WriteLine("Введите секретный ключ: ");
                secretKey = Console.ReadLine();
                Console.WriteLine("Введите вектор инициализации: ");
                initVector = Console.ReadLine();

                string command = "";
                while (command != "0")
                {
                    if (operatingMode == "encrypt")
                    {
                        Console.WriteLine(
                            "Схема шифрования: " + cipherMode + "\n" +
                            "Шифруемая строка: " + data + "\n" +
                            "Секретный ключ: " + secretKey + "\n" +
                            "Вектор инициализации: " + initVector + "\n" +
                            "Для изменения параметров введите:\n" +
                            "1 - для изменения схемы шифрования\n" +
                            "2 - для изменения шифруемой строки\n" +
                            "3 - для изменения секретного ключа\n" +
                            "4 - для изменения вектора инициализации\n" +
                            "Введите 0 для запуска шифрования"
                        );
                    }
                    else if (operatingMode == "decrypt")
                    {
                        Console.WriteLine(
                            "Схема дешифрования: " + cipherMode + "\n" +
                            "Зашифрованная строка: " + data + "\n" +
                            "Секретный ключ: " + secretKey + "\n" +
                            "Вектор инициализации: " + initVector + "\n" +
                            "Для изменения параметров введите:\n" +
                            "1 - для изменения схемы дешифрования\n" +
                            "2 - для изменения зашифрованной строки\n" +
                            "3 - для изменения секретного ключа\n" +
                            "4 - для изменения вектора инициализации\n" +
                            "Введите 0 для запуска дешифрования"
                        );
                    }
                    command = Console.ReadLine();
                    if (command == "1")
                    {
                        if (operatingMode == "encrypt")
                        {
                            Console.Write("Введите схему шифрования: (ECB, CBC, OFB, CFB, CTS)");
                        }
                        else if (operatingMode == "decrypt")
                        {
                            Console.Write("Введите схему дешифрования: (ECB, CBC, OFB, CFB, CTS)");
                        }
                        cipherMode = Console.ReadLine();
                    }
                    else if (command == "2")
                    {
                        if (operatingMode == "encrypt")
                        {
                            Console.Write("Введите шифруемую строку: ");
                        }
                        else if (operatingMode == "decrypt")
                        {
                            Console.Write("Введите зашифрованную строку в формате base64: ");
                        }
                        data = Console.ReadLine();
                    }
                    else if (command == "3")
                    {
                        Console.Write("Введите секретный ключ: ");
                        secretKey = Console.ReadLine();
                    }
                    else if (command == "4")
                    {
                        Console.Write("Введите вектор инициализации: ");
                        initVector = Console.ReadLine();
                    }
                }
            }

            public void StartEncrypt()
            {
                ReadParams("encrypt");

                Cryption cript = new Cryption(secretKey, initVector);
                byte[] encrypted_byte = cript.Encrypt(data, cipherMode);

                Console.WriteLine("Зашифрованная строка в 16-ом виде: " +
                    System.BitConverter.ToString(encrypted_byte) + "\n" +
                    "Зашифрованная строка в base64: " +
                    Convert.ToBase64String(encrypted_byte));
            }
            public void StartDecrypt()
            {
                ReadParams("decrypt");

                Cryption cript = new Cryption(secretKey, initVector);
                string decrypted = cript.Decrypt(data, cipherMode);

                Console.WriteLine("Расшифрованная строка: " + decrypted);
            }
        }

        public sealed class Cryption
        {
            private RijndaelManaged Algorithm; //Security.Cryptography.RijndaelManaged
            private MemoryStream openStream; //Управляемая версия Security.Cryptography.Rijndael
            private ICryptoTransform EncryptorDecryptor; //interface Security.Cryptography.ICryptoTransform
            private CryptoStream crStream; //Security.Cryptography.CryptoStream связывает потоки с криптографическим преобразованием
            private StreamWriter strWriter;
            private StreamReader strReader;

            private string key_str;
            private string iv_str;

            private byte[] key_byte;
            private byte[] iv_byte;

            private string pwd_str;
            private byte[] pwd_byte;

            public Cryption(string key_val, string iv_val)
            {
                ChangeKey(key_val);
                ChangeIV(iv_val);
            }

            public void ChangeKey(string key_val)
            {
                key_byte = new byte[32];
                key_str = key_val;

                for (int i = 0; i < key_str.Length; i++)
                {
                    key_byte[i] = Convert.ToByte(key_str[i]);
                }
            }
            public void ChangeIV(string iv_val)
            {
                iv_byte = new byte[32];
                iv_str = iv_val;

                for (int i = 0; i < iv_str.Length; i++)
                {
                    iv_byte[i] = Convert.ToByte(iv_str[i]);
                }
            }

            public RijndaelManaged ConstructManager(string cipherMode)
            {
                Algorithm = new RijndaelManaged();

                Algorithm.BlockSize = 256;
                Algorithm.KeySize = 256;
                if (cipherMode == "ECB")
                {
                    Algorithm.Mode = CipherMode.ECB;
                }
                else if (cipherMode == "CBC")
                {
                    Algorithm.Mode = CipherMode.CBC;
                }
                else if (cipherMode == "OFB")
                {
                    Algorithm.Mode = CipherMode.OFB;
                }
                else if (cipherMode == "CFB")
                {
                    Algorithm.Mode = CipherMode.CFB;
                }
                else if (cipherMode == "CTS")
                {
                    Algorithm.Mode = CipherMode.CTS;
                }
                return Algorithm;
            }

            public byte[] Encrypt(string s, string cipherMode)
            {
                Algorithm = ConstructManager(cipherMode);

                openStream = new MemoryStream();

                EncryptorDecryptor = Algorithm.CreateEncryptor(key_byte, iv_byte);

                crStream = new CryptoStream(openStream, EncryptorDecryptor, CryptoStreamMode.Write);
                strWriter = new StreamWriter(crStream); //инициализация экз класса для потока UTF8 и буфера размером по умолччанию
                strWriter.Write(s);//Запись строки s в поток

                strWriter.Flush();//очистка всех буферов strWriter для защиты от переполнения
                crStream.FlushFinalBlock();//обновляет состояние нижележащего источника данных с текущим состоянием буфера, затем обнуляет буфер
                pwd_byte = new byte[openStream.Length];
                openStream.Position = 0; //устанавливаем текущую позицию в потоке
                openStream.Read(pwd_byte, 0, (int)pwd_byte.Length);// считываем блок байт из потока в буфер

                pwd_str = new UnicodeEncoding().GetString(pwd_byte);

                strWriter.Close();
                crStream.Close();
                openStream.Close();

                return pwd_byte;
            }

            public string Decrypt(string s, string cipherMode)
            {
                Algorithm = ConstructManager(cipherMode);

                openStream = new MemoryStream(Convert.FromBase64String(s));

                EncryptorDecryptor = Algorithm.CreateDecryptor(key_byte, iv_byte);
                openStream.Position = 0;
                crStream = new CryptoStream(openStream, EncryptorDecryptor, CryptoStreamMode.Read);
                strReader = new StreamReader(crStream);

                string result = strReader.ReadToEnd();

                strReader.Close();
                crStream.Close();
                openStream.Close();

                return result;
            }
        }
    }
}
