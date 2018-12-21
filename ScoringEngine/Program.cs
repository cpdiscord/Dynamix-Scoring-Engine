using IWshRuntimeLibrary;
using Microsoft.Win32;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Management;
using System.ServiceProcess;
using File = System.IO.File;

namespace ScoringEngine
{
    class Program
    {
        static void Main(string[] args)
        {
            AppShortcutToDesktop();
            Run();
        }
        public static void Run()
        {
            System.Threading.Thread.Sleep(30000); //Sleeps for 30 seconds before running again. This is just a loop.
            Run();
        }


        public static void FileDetection(string location) //Detects if file has been removed.
        {
            bool exists = File.Exists(location);
            if (exists == false)
            {
                HtmlScoring("File: " + '"' + location + '"' + " has been removed");
            }
        }


        public static void ForensicsCheck(string location, string answer) //Forensics checker, grabs location and searches for the string "answer"
        {
            {
                string line;
                System.IO.StreamReader file = new System.IO.StreamReader(@location);
                while ((line = file.ReadLine()) != null)
                {
                    if (line.Contains(answer))
                    {
                        string fileName = Path.GetFileNameWithoutExtension(@location); //Gets the filename from location
                        HtmlScoring(fileName + " has been answered correctly"); //So this would output "Forensics question 1 has been answered correctly" or something similar
                    }
                }
            }
        }


        public static void FirewallCheck() //Grabs the status of the firewall
        {
            Type FWManagerType = Type.GetTypeFromProgID("HNetCfg.FwMgr");
            dynamic FWManager = Activator.CreateInstance(FWManagerType);
            if (Convert.ToString(FWManager.LocalPolicy.CurrentProfile.FirewallEnabled) == "True")
            {
                HtmlScoring("Firewall has been enabled");
            }
            else { }
        }


        public static void UserLockout(string user) //Grabs if the user is locked out or not
        {
            SelectQuery query = new SelectQuery("Win32_UserAccount", "Name=" + "'" + user + "'");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject userObj in searcher.Get())
            {
                if (userObj["Lockout"].ToString() == "False") //Added .ToString() so if would stop complaining
                {
                    HtmlScoring(user + " has been unlocked");
                }
            }
        }
        public static void UserDisabled(string user) //Grabs if the user is disabled or not
        {
            SelectQuery query = new SelectQuery("Win32_UserAccount", "Name=" + "'" + user + "'");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject userObj in searcher.Get())
            {
                if (userObj["Disabled"].ToString() == "False")
                {
                    HtmlScoring(user + " has been enabled");
                }
            }
        }
        public static void UserPasswordChangeable(string user) //Grabs if the users password is changeable or not.
        {
            SelectQuery query = new SelectQuery("Win32_UserAccount", "Name=" + "'" + user + "'");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject userObj in searcher.Get())
            {
                if (userObj["PasswordChangeable"].ToString() == "True")
                {
                    HtmlScoring(user + "'s password is changeable");
                }
            }
        }


        public static void ProgramVersionCheck(string location, string desiredVersion) //Checks the version of an exe and compares it to the desiredVersion.
        {
            FileVersionInfo program = FileVersionInfo.GetVersionInfo(@location);
            string programVersion = program.FileVersion;
            string fileName = Path.GetFileNameWithoutExtension(@location);
            var result = programVersion.CompareTo(desiredVersion);
            if (result > 0)
            {
                HtmlScoring(fileName + " has been updated to the latest version");
            }
            else if (result < 0) { }
            else
            {
                HtmlScoring(fileName + " has been updated to the latest version");
            }
        }


        public static void ShareDetection(string desiredShare) //Detects if a share exists or not
        {
            using (ManagementClass shares = new ManagementClass(@"\\Localhost", "Win32_Share", new ObjectGetOptions()))
            {
                List<string> activeShares = new List<string>();
                foreach (ManagementObject share in shares.GetInstances())
                {
                    activeShares.Add(share["Name"].ToString());
                }
                bool inList = activeShares.Contains(desiredShare);
                if (inList == false)
                {
                    HtmlScoring(desiredShare + " has been deleted");
                }
                else { }
            }
        }


        public static void ServiceRunning(string service) //Checks if a service is running
        {
            ServiceController sc = new ServiceController(service);
            if (sc.Status.ToString() == "Running")
            {
                HtmlScoring(service + " is running");
            }
            else { }
        }
        public static void ServiceStopped(string service) // Checks if a service is stopped
        {
            ServiceController sc = new ServiceController(service);
            if (sc.Status.ToString() == "Stopped")
            {
                HtmlScoring(service + " is stopped");
            }
            else { }
        }


        public static void LSPMinimumPasswordAge() //Checks if the MinimumPasswordAge is between 1-30
        {
            string[] lines = System.IO.File.ReadAllLines(@"C:\DyNaMiX\Current-Policy.txt");
            string minimumPassword = Array.Find(lines,
               element => element.StartsWith("MinimumPasswordAge = ", StringComparison.Ordinal));

            string temp = minimumPassword.Split(new string[] { "MinimumPasswordAge = " }, StringSplitOptions.None).Last();

            int.TryParse(temp, out int minimumPasswordVal);
            if (minimumPasswordVal > 0)
            {
                if (30 >= minimumPasswordVal)
                {
                    HtmlScoring("Minimum Password Age has been set");
                }
            }
        }
        public static void LSPMaximumPasswordAge() //Checks if the MaximumPasswordAge is between 30-90
        {
            string[] lines = System.IO.File.ReadAllLines(@"C:\DyNaMiX\Current-Policy.txt");
            string maximumPassword = Array.Find(lines,
               element => element.StartsWith("MaximumPasswordAge = ", StringComparison.Ordinal));

            string temp = maximumPassword.Split(new string[] { "MaximumPasswordAge = " }, StringSplitOptions.None).Last();

            int.TryParse(temp, out int maximumPasswordVal);
            if (maximumPasswordVal >= 30)
            {
                if (90 >= maximumPasswordVal)
                {
                    HtmlScoring("Maximum Password Age has been set");
                }
            }
        }
        public static void LSPPasswordComplexity() //Checks if PasswordComplexity is set to 1 (Enabled)
        {
            string[] lines = System.IO.File.ReadAllLines(@"C:\DyNaMiX\Current-Policy.txt");
            string passwordComplexity = Array.Find(lines,
               element => element.StartsWith("PasswordComplexity = ", StringComparison.Ordinal));
            string temp = passwordComplexity.Split(new string[] { "PasswordComplexity = " }, StringSplitOptions.None).Last();

            int.TryParse(temp, out int passwordComplexityVal);
            if (passwordComplexityVal == 1)
            {
                HtmlScoring("Password Complexity has been set");
            }
        }


        public static void OptionFeatureDisable(string feature) //Detects if an optional feature is disabled
        {
            SelectQuery query = new SelectQuery("Win32_OptionalFeature", "Name=" + "'" + feature + "'" + '"');
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject envVar in searcher.Get())
            {
                if (envVar["InstallState"].ToString() == "2")
                {
                    HtmlScoring(feature + "has been disabled");
                }
            }
        }
        public static void OptionFeatureEnable(string feature) //Detects if an optional feature is enabled
        {
            SelectQuery query = new SelectQuery("Win32_OptionalFeature", "Name=" + "'" + feature + "'" + '"');
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject envVar in searcher.Get())
            {
                if (envVar["InstallState"].ToString() == "1")
                {
                    HtmlScoring(feature + "has been enabled");
                }
            }
        }


        public static void IsProgramInstalled(string program) //Guess what, it detects if it's installed
        {
            if (SoftwareName(program) == true)
            {
                HtmlScoring(program + " has been installed");
            }
        }
        public static void IsProgramUninstalled(string program) //Detects if it's uninstalled
        {
            if (SoftwareName(program) == false)
            {
                HtmlScoring(program + " has been uninstalled");
            }
        }


        public static void GroupMembershipTrue(string user, string groupName)
        {
            using (DirectoryEntry machine = new DirectoryEntry("WinNT://localhost"))
            {
                using (DirectoryEntry group = machine.Children.Find(groupName, "Group"))
                {
                    List<string> groupMembers = new List<string>();
                    object members = group.Invoke("Members", null);
                    foreach (object member in (IEnumerable)members)
                    {
                        string accountName = new DirectoryEntry(member).Name;
                        groupMembers.Add(accountName);
                    }
                    if (groupMembers.Contains(user) == true)
                    {
                        HtmlScoring(user + " is apart of " + groupName);
                    }
                }
            }
        }
        public static void GroupMembershipFalse(string user, string groupName)
        {
            using (DirectoryEntry machine = new DirectoryEntry("WinNT://localhost"))
            {
                using (DirectoryEntry group = machine.Children.Find(groupName, "Group"))
                {
                    List<string> groupMembers = new List<string>();
                    object members = group.Invoke("Members", null);
                    foreach (object member in (IEnumerable)members)
                    {
                        string accountName = new DirectoryEntry(member).Name;
                        groupMembers.Add(accountName);
                    }
                    if (groupMembers.Contains(user) == false)
                    {
                        HtmlScoring(user + " is not apart of " + groupName);
                    }
                }
            }
        }


        public static void GroupExistTrue(string group)
        {
            var machine = Environment.MachineName;
            var server = new DirectoryEntry(string.Format("WinNT://{0},Computer", machine));
            bool exists = server.Children.Cast<DirectoryEntry>().Any(d => d.SchemaClassName.Equals("Group") && d.Name.Equals(group));
            if (exists == true)
            {
                HtmlScoring(group + " exists");
            }
        }
        public static void GroupExistFalse(string group)
        {
            var machine = Environment.MachineName;
            var server = new DirectoryEntry(string.Format("WinNT://{0},Computer", machine));
            bool exists = server.Children.Cast<DirectoryEntry>().Any(d => d.SchemaClassName.Equals("Group") && d.Name.Equals(group));
            if (exists == false)
            {
                HtmlScoring(group + " does not exist");
            }
        }



        public static void HtmlScoring(string text) //Outputs input above "</ul>"
        {
            string location = @"C:\\DyNaMiX\\score_report.html";
            string lineToFind = "</ul>";

            List<string> lines = File.ReadLines(location).ToList();
            int index = lines.IndexOf(lineToFind);
            lines.Insert(index, "<li>" + text + "</li>");
            File.WriteAllLines(location, lines);
        }

        public static void AppShortcutToDesktop() //Creates a shortcut to the desktop. 
        {
            string deskDir = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);

            WshShell wsh = new WshShell();
            IWshRuntimeLibrary.IWshShortcut shortcut = wsh.CreateShortcut(
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + "\\Scoring Report.lnk") as IWshRuntimeLibrary.IWshShortcut;
            shortcut.Arguments = "";
            shortcut.TargetPath = "C:\\DyNaMiX\\score_report.html";
            shortcut.WindowStyle = 1;
            shortcut.Description = "Windows Scoring Report";
            shortcut.WorkingDirectory = "c:\\DyNaMiX";
            shortcut.IconLocation = "C:\\DyNaMiX\\dx-128-icon.ico";
            shortcut.Save();
        }

        //public static void CreateHTML(string currentVulns, string totalVulns)
        //{
        //    File.Delete(@"C:\DyNaMiX\score_report.html");
        //    File.Copy(@"C:\DyNaMiX\base_report.html", @"C:\DyNaMiX\score_report.html");

        //    string location = @"C:\DyNaMiX\score_report.html";
        //    string lineToFind = "<br>";

        //    List<string> lines = File.ReadLines(location).ToList();
        //    int index = lines.IndexOf(lineToFind);
        //    lines.Insert(index, "<center><h2>Vulnerabilities fixed: " + currentVulns + "/" + totalVulns + "</h2></center>");
        //    File.WriteAllLines(location, lines);
        //}

        public static void ExportLSP() //Exports Local Security Policy
        {
            //This has to be run as admin
            System.Diagnostics.Process process = new System.Diagnostics.Process();
            System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo
            {
                WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden,
                FileName = "cmd.exe",
                Arguments = "/C SecEdit /export /cfg c:\\DyNaMiX\\Current-Policy.txt"
            };
            process.StartInfo = startInfo;
            process.Start();
        }

        private static bool SoftwareName(string softwareName)
        {
            var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") ??
                      Registry.LocalMachine.OpenSubKey(
                          @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall");

            if (key == null)
                return false;

            return key.GetSubKeyNames()
                .Select(keyName => key.OpenSubKey(keyName))
                .Select(subkey => subkey.GetValue("DisplayName") as string)
                .Any(displayName => displayName != null && displayName.Contains(softwareName));
        }
    }
}