using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace RSA_GUI
{
    public partial class KeyGenerator : Form
    {
        [DllImport("E:\\Workspace\\RSA\\RSA_DLL\\x64\\Debug\\RSA_DLL.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, EntryPoint = "KeyGen")]
        public static extern void KeyGen(string keyFormat, int keySize, string privateFile, string publicFile);

        /*
        DLL_EXPORT void KeyGen(const char* keyFormat, const int& keySize, const char* privateFile, const char* publicFile);
        DLL_EXPORT void Encrypt(const char* keyFormat, const char* publicFile, const char* plainTextFile, const char* cipherTextFile);
        DLL_EXPORT void Decrypt(const char* keyFormat, const char* privateFile, const char* recoveredTextFile, const char* cipherTextFile);
        */
        public KeyGenerator()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            string keyFormat = comboBox1.SelectedItem.ToString();
            int keySize = int.Parse(textBox1.Text);
            string privateFile = textBox2.Text;
            string publicFile = textBox3.Text;
            KeyGen(keyFormat, keySize, privateFile, publicFile);
            MessageBox.Show("Keys generated successfully!");
        }

        private void button2_Click(object sender, EventArgs e)
        {
            this.Close();
            Menu menu = new Menu();
            menu.Show();
        }
    }
}
