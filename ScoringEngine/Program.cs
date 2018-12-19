using IWshRuntimeLibrary;
using System;
using System.Collections.Generic;
using System.Diagnostics;
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
                string scoring = "File: " + '"' + location + '"' + " has been removed";
                HtmlScoring(scoring);
            }
        }


        public static void ForensicsCheck(string location, string answer) //Forensics checker, grabs location and searches for the string answer
        {
            {
                string line;
                System.IO.StreamReader file = new System.IO.StreamReader(@location);
                while ((line = file.ReadLine()) != null)
                {
                    if (line.Contains(answer))
                    {
                        string fileName = Path.GetFileNameWithoutExtension(@location); //Gets the filename from location
                        HtmlScoring(fileName + " has been answered correctly."); //So this would output "Forensics question 1 has been answered correctly" or something similar
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
                    HtmlScoring(user + " has been unlocked.");
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
                    HtmlScoring(user + " has been enabled.");
                }
            }
        }
        public static void UserPasswordChangeable(string user) //Grabs it it password is changeable or not.
        {
            SelectQuery query = new SelectQuery("Win32_UserAccount", "Name=" + "'" + user + "'");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject userObj in searcher.Get())
            {
                if (userObj["PasswordChangeable"].ToString() == "True")
                {
                    HtmlScoring(user + "'s password is changeable.");
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
                HtmlScoring(fileName + " has been updated to the latest version.");
            }
            else if (result < 0) { }
            else
            {
                HtmlScoring(fileName + " has been updated to the latest version.");
            }
        }


        public static void ShareDetection(string desiredShare)
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
                    HtmlScoring(desiredShare + " has been deleted.");
                }
                else { }
            }
        }


        public static void ServiceRunning(string service)
        {
            ServiceController sc = new ServiceController(service);
            if (sc.Status.ToString() == "Running")
            {
                HtmlScoring(service + " is running");
            }
            else { }
        }
        public static void ServiceStopped(string service)
        {
            ServiceController sc = new ServiceController(service);
            if (sc.Status.ToString() == "Stopped")
            {
                HtmlScoring(service + " is stopped");
            }
            else { }
        }



        public static void HtmlScoring(string text) //A simple script to output any lines above the </ul>
        {
            string location = @"C:\Users\Henry\Desktop\yeet.txt";
            string lineToFind = "</ul>";

            List<string> lines = File.ReadLines(location).ToList();
            int index = lines.IndexOf(lineToFind);
            lines.Insert(index, "<li>" + text + "</li>");
            File.WriteAllLines(location, lines);
        }

        public static void AppShortcutToDesktop()
        {
            string deskDir = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);

            WshShell wsh = new WshShell();
            IWshRuntimeLibrary.IWshShortcut shortcut = wsh.CreateShortcut(
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + "\\Scoring Report.lnk") as IWshRuntimeLibrary.IWshShortcut;
            shortcut.Arguments = "";
            shortcut.TargetPath = "C:\\DyNaMiX\\score_report.html";
            // not sure about what this is for
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
    }
}