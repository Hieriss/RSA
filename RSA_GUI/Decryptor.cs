﻿using System;
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
    public partial class Decryptor : Form
    {
        [DllImport("E:\\Workspace\\RSA\\RSA_DLL\\x64\\Debug\\RSA_DLL.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, EntryPoint = "KeyGen")]
        public static extern void Decrypt(string keyFormat, string privateFile, string recoveredTextFile, string cipherTextFile);

        public Decryptor()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            string keyFormat = comboBox1.SelectedItem.ToString();
            string publicFile = textBox3.Text;
            string recoveredTextFile = textBox1.Text;
            string cipherTextFile = textBox4.Text;
            Decrypt(keyFormat, publicFile, recoveredTextFile, cipherTextFile);
            MessageBox.Show("Decryption successful!");
        }

        private void button2_Click(object sender, EventArgs e)
        {
            this.Close();
            Menu menu = new Menu();
            menu.Show();
        }
    }
}
