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
            Console.Write("Введите шифруемую строку: ");
            string clearText = Console.ReadLine();
            Console.Write("Введите секретный ключ: ");
            string secretKey = Console.ReadLine();
            Console.Write("Введите вектор инициализации: ");
            string initVector = Console.ReadLine();

            string command = "";
            while (command != "0")
            {
                Console.WriteLine("Шифруемая строка: " + clearText);
                Console.WriteLine("Секретный ключ: " + secretKey);
                Console.WriteLine("Вектор инициализации: " + initVector);
                Console.WriteLine("Для изменения параметров введите:\n" +
                    "1 - для изменения шифруемой строки\n" +
                    "2 - для изменения секретного ключа\n" +
                    "3 - для изменения вектора инициализации\n" +
                    "Введите 0 для запуска шифрования");
                command = Console.ReadLine();

                if (command == "1")
                {
                    Console.Write("Введите шифруемую строку: ");
                    clearText = Console.ReadLine();
                }
                else if (command == "2")
                {
                    Console.Write("Введите секретный ключ: ");
                    secretKey = Console.ReadLine();
                }
                else if (command == "3")
                {
                    Console.Write("Введите вектор инициализации: ");
                    initVector = Console.ReadLine();
                }
            }

            Cryption cript = new Cryption(secretKey, initVector);

            string data = cript.Encrypt(clearText);

            Console.WriteLine("Зашифрованная строка: " + data);

            string decrypted = cript.Decrypt(Console.ReadLine());
            Console.WriteLine("Decrypted String: " + decrypted);
            Console.ReadLine();

        }

		public sealed class Cryption
		{
			private RijndaelManaged Algorithm;              //Security.Cryptography.RijndaelManaged
			private MemoryStream openStream;                //Управляемая версия Security.Cryptography.Rijndael
			private ICryptoTransform EncryptorDecryptor;    //interface Security.Cryptography.ICryptoTransform
			private CryptoStream crStream;                  //Security.Cryptography.CryptoStream связывает потоки с криптографическим преобразованием
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
				key_byte = new byte[32];
				iv_byte = new byte[32];

				int i;
				key_str = key_val;
				iv_str = iv_val;

/*              key = ASCIIEncoding.ASCII.GetBytes(m_key);
                iv = ASCIIEncoding.ASCII.GetBytes(m_iv);*/

				for (i = 0; i < key_str.Length; i++)
				{
					key_byte[i] = Convert.ToByte(key_str[i]);
				}
				for (i = 0; i < iv_str.Length; i++)
				{
					iv_byte[i] = Convert.ToByte(iv_str[i]);
				}
			}

			public string Encrypt(string s)
			{
				Algorithm = new RijndaelManaged();

				Algorithm.BlockSize = 256;
				Algorithm.KeySize = 256;
                //Algorithm.Mode = CipherMode.CBC;

                openStream = new MemoryStream();

				EncryptorDecryptor = Algorithm.CreateEncryptor(key_byte, iv_byte);

				crStream = new CryptoStream(openStream, EncryptorDecryptor, CryptoStreamMode.Write);
				strWriter = new StreamWriter(crStream);                 //инициализация экз класса для потока UTF8 и буфера размером по умолччанию
				strWriter.Write(s);                                     //Запись строки s в поток

				strWriter.Flush();                                      //очистка всех буферов strWriter для защиты от переполнения
				crStream.FlushFinalBlock();                             //обновляет состояние нижележащего источника данных с текущим состоянием буфера, затем обнуляет буфер
				pwd_byte = new byte[openStream.Length];
                openStream.Position = 0;                                //устанавливаем текущую позицию в потоке
                openStream.Read(pwd_byte, 0, (int)pwd_byte.Length);     //считываем блок байт из потока в буфер

                pwd_str = new UnicodeEncoding().GetString(pwd_byte);

                Console.WriteLine(System.BitConverter.ToString(pwd_byte));

                strWriter.Close();
                crStream.Close();
                openStream.Close();

                return Convert.ToBase64String(pwd_byte);
			}

			public string Decrypt(string s)
			{
				Algorithm = new RijndaelManaged();

				Algorithm.BlockSize = 256;
				Algorithm.KeySize = 256;
                //Algorithm.Mode = CipherMode.CBC;

                openStream = new MemoryStream(Convert.FromBase64String(s));

				EncryptorDecryptor = Algorithm.CreateDecryptor(key_byte, iv_byte);
                openStream.Position = 0;
				crStream = new CryptoStream(openStream, EncryptorDecryptor, CryptoStreamMode.Read);
				strReader = new StreamReader(crStream);

                string result = strReader.ReadToEnd();

                strWriter.Close();
                crStream.Close();
                openStream.Close();

                return result;
			}
		}
	}
}

