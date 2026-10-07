// Synthetic-only AppContainer launcher. No production override or fallback.
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Text.RegularExpressions;
class AppContainerLauncher {
 [StructLayout(LayoutKind.Sequential)] struct SI { public int cb; public IntPtr reserved,desktop,title; public int x,y,xs,ys,xc,yc,fill,flags; public short show,reserved2; public IntPtr reserved3,input,output,error; }
 [StructLayout(LayoutKind.Sequential)] struct SIX { public SI si; public IntPtr attrs; }
 [StructLayout(LayoutKind.Sequential)] struct PI { public IntPtr process,thread; public int pid,tid; }
 [StructLayout(LayoutKind.Sequential)] struct CAPS { public IntPtr sid,capabilities; public int count,reserved; }
 [StructLayout(LayoutKind.Sequential)] struct LIMIT { public long processTime,jobTime; public uint flags; public UIntPtr minWorking,maxWorking; public uint activeProcesses; public UIntPtr affinity; public uint priority,scheduling; }
 [StructLayout(LayoutKind.Sequential)] struct IO { public ulong readOps,writeOps,otherOps,readBytes,writeBytes,otherBytes; }
 [StructLayout(LayoutKind.Sequential)] struct EXTENDED { public LIMIT basic; public IO io; public UIntPtr processMemory,jobMemory,peakProcess,peakJob; }
 [DllImport("userenv.dll",CharSet=CharSet.Unicode)] static extern int CreateAppContainerProfile(string name,string display,string desc,IntPtr caps,uint n,out IntPtr sid);
 [DllImport("userenv.dll",CharSet=CharSet.Unicode)] static extern int DeriveAppContainerSidFromAppContainerName(string name,out IntPtr sid);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertSidToStringSid(IntPtr sid,out IntPtr text);
 [DllImport("advapi32.dll")] static extern IntPtr FreeSid(IntPtr sid);
 [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,int flags,ref IntPtr size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,IntPtr size,IntPtr prev,IntPtr ret);
 [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessW(string exe,StringBuilder command,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string cwd,ref SIX si,out PI pi);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr CreateJobObjectW(IntPtr attrs,IntPtr name);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,ref EXTENDED info,uint size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
 [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint ms);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr handle,out uint code);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr handle,uint code);
 static string Q(string s) { if(s.Contains("\"") || s.EndsWith("\\")) throw new Exception("Invalid argument");return "\""+s+"\""; }
 static void SafePath(string path) {
  string full=Path.GetFullPath(path), drive=Path.GetPathRoot(full);
  if(full.StartsWith("\\") || new DriveInfo(drive).DriveType!=DriveType.Fixed || full.Substring(drive.Length).Contains(":"))throw new Exception("LOCAL_FIXED_PATH_REQUIRED");
  string current=drive;
  foreach(string part in full.Substring(drive.Length).Split(Path.DirectorySeparatorChar)) {
   if(part.Length==0)continue;
   if(part.EndsWith(".") || part.EndsWith(" ") || Regex.IsMatch(part,@"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)",RegexOptions.IgnoreCase))throw new Exception("UNSAFE_PATH_COMPONENT");
   current=Path.Combine(current,part);
   // GetAttributes detects even a dangling reparse point when it is accessible.
   try { if((File.GetAttributes(current)&FileAttributes.ReparsePoint)!=0)throw new Exception("REPARSE_POINT_DENIED"); }
   catch(FileNotFoundException) { } catch(DirectoryNotFoundException) { }
  }
 }
 static IEnumerable<string> Files(string folder) {
  SafePath(folder);
  foreach(string p in Directory.GetFileSystemEntries(folder)) {
   SafePath(p);
   if(Directory.Exists(p)) {foreach(string file in Files(p))yield return file;} else yield return p;
  }
 }
 static string Digest(string path) {using(var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(file)).Replace("-","").ToLowerInvariant();}
 static void VerifyIntegrity(string root) {
  string seal=Path.Combine(root,"build","offline-integrity.tsv");SafePath(seal);
  if(!File.Exists(seal))throw new Exception("OFFLINE_INSTALLATION_SEAL_REQUIRED");
  var lines=File.ReadAllLines(seal,Encoding.UTF8);
  if(lines.Length<2 || lines[0]!="LAYA_OFFLINE_INTEGRITY_V1")throw new Exception("INVALID_INSTALLATION_SEAL");
  var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
  for(int i=1;i<lines.Length;i++) {
   string[] row=lines[i].Split('\t');
   if(row.Length!=2 || !Regex.IsMatch(row[0],"^[0-9a-f]{64}$") || row[1].Contains("\\") || row[1].Contains(":") || row[1].StartsWith("/") || row[1].Split('/').Length==0)throw new Exception("INVALID_SEAL_ROW");
   foreach(string part in row[1].Split('/'))if(part==".." || part=="." || part.Length==0)throw new Exception("INVALID_SEAL_PATH");
   string p=Path.GetFullPath(Path.Combine(root,row[1]));SafePath(p);
   if(!p.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)||!seen.Add(p))throw new Exception("INVALID_SEAL_PATH");
   if(Digest(p)!=row[0])throw new Exception("INSTALLATION_HASH_MISMATCH");
  }
  foreach(string required in new[]{"runtime-v2/python.exe","scripts/offline_worker.py","scripts/security_policy.py","scripts/native_probe.py","tests/synthetic-ko.json","prepared-model-manifest.json","build/LayaLauncher.exe"})
   if(!seen.Contains(Path.GetFullPath(Path.Combine(root,required))))throw new Exception("INCOMPLETE_INSTALLATION_SEAL");
  foreach(string folder in new[]{"runtime-v2","models/laya-multilingual-prepared","scripts"})foreach(string p in Files(Path.Combine(root,folder)))if(!seen.Contains(p))throw new Exception("UNEXPECTED_INSTALLED_FILE");
  Console.WriteLine("Installation integrity verified; files="+seen.Count+"; business input disabled");
 }
 static void Grant(string path,string sid,string access) {
  SafePath(path);bool folder=Directory.Exists(path);
  if(folder)foreach(string file in Files(path)) { }
  var p=Process.Start(new ProcessStartInfo {FileName=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"icacls.exe"),Arguments=Q(path)+" /grant *"+sid+":"+(folder?"(OI)(CI)":"")+access+(folder?" /T /Q":" /Q"),UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true});
  p.StandardOutput.ReadToEnd();p.StandardError.ReadToEnd();p.WaitForExit();if(p.ExitCode!=0)throw new Exception("ACL_SETUP_FAILED");p.Dispose();
 }
 static int Main(string[] args) {
  IntPtr sid=IntPtr.Zero,attrs=IntPtr.Zero,cp=IntPtr.Zero,ep=IntPtr.Zero,job=IntPtr.Zero;PI pi=new PI();bool attrReady=false,completed=false;
  try {
   bool setup=args.Length==1 && args[0]=="--setup";
   if(!setup && (args.Length!=2 || (args[0]!="probe" && args[0]!="native-probe" && args[0]!="guard-check" && args[0]!="evaluate")))throw new Exception("Production input is disabled; BUSINESS_INPUT_DISABLED. Use --setup or a synthetic test mode.");
   string root=Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,".."));SafePath(root);
   string privateDir=Path.Combine(root,"private"),request=null;
   if(!setup) {
    request=Path.GetFullPath(args[1]);SafePath(request);
    if(!String.Equals(Path.GetDirectoryName(request),privateDir,StringComparison.OrdinalIgnoreCase) || !Regex.IsMatch(Path.GetFileName(request),"^[A-Za-z0-9][A-Za-z0-9_-]{0,90}\\.json$"))throw new Exception("Request must be inside private directory with a synthetic basename");
    if(File.Exists(request))throw new Exception("INPUT_FILE_NOT_ACCEPTED");
    string result=Path.ChangeExtension(request,".result.json");SafePath(result);if(File.Exists(result))throw new Exception("RESULT_EXISTS_PRESERVED");
   }
   VerifyIntegrity(root);
   string hash=BitConverter.ToString(SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(root.ToLowerInvariant()))).Replace("-","").Substring(0,20);
   string name="LayaLocal."+hash+".v2";
   if(setup) {
    int hr=CreateAppContainerProfile(name,name,"Synthetic offline local decisions",IntPtr.Zero,0,out sid);
    if(hr!=0 && hr!=unchecked((int)0x800700B7))Marshal.ThrowExceptionForHR(hr);
    if(hr!=0)Marshal.ThrowExceptionForHR(DeriveAppContainerSidFromAppContainerName(name,out sid));
   } else Marshal.ThrowExceptionForHR(DeriveAppContainerSidFromAppContainerName(name,out sid));
   IntPtr text;if(!ConvertSidToStringSid(sid,out text))throw new Exception("SID_FAILED");string sidStr=Marshal.PtrToStringUni(text);LocalFree(text);
   if(setup) {
    foreach(string folder in new[]{"runtime-v2","models/laya-multilingual-prepared","scripts","tests"})Grant(Path.Combine(root,folder),sidStr,"RX");
    Grant(Path.Combine(root,"prepared-model-manifest.json"),sidStr,"R");
    SafePath(Path.Combine(privateDir,"tmp"));Directory.CreateDirectory(Path.Combine(privateDir,"tmp"));Grant(privateDir,sidStr,"M");
    Console.WriteLine("Synthetic setup complete; zero network capabilities; business input disabled");return 0;
   }
   string exe=Path.Combine(root,"runtime-v2","python.exe"),script=Path.Combine(root,"scripts","offline_worker.py");
   var cmd=new StringBuilder(Q(exe)+" -I -S -B "+Q(script)+" "+args[0]+" "+Q(request));
   IntPtr size=IntPtr.Zero;InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref size);attrs=Marshal.AllocHGlobal(size);
   if(!InitializeProcThreadAttributeList(attrs,1,0,ref size))throw new Exception("ATTRIBUTE_LIST_FAILED");attrReady=true;
   CAPS caps=new CAPS {sid=sid,capabilities=IntPtr.Zero,count=0,reserved=0};cp=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CAPS)));Marshal.StructureToPtr(caps,cp,false);
   if(!UpdateProcThreadAttribute(attrs,0,(IntPtr)0x20009,cp,(IntPtr)Marshal.SizeOf(typeof(CAPS)),IntPtr.Zero,IntPtr.Zero))throw new Exception("SECURITY_CAPABILITIES_FAILED");
   job=CreateJobObjectW(IntPtr.Zero,IntPtr.Zero);if(job==IntPtr.Zero)throw new Exception("ISOLATION_JOB_REQUIRED");
   EXTENDED limits=new EXTENDED();limits.basic.flags=0x2000|0x8;limits.basic.activeProcesses=1;
   if(!SetInformationJobObject(job,9,ref limits,(uint)Marshal.SizeOf(typeof(EXTENDED))))throw new Exception("ISOLATION_JOB_LIMITS_REQUIRED");
   string win=Environment.GetFolderPath(Environment.SpecialFolder.Windows);
   var env=new SortedDictionary<string,string>(StringComparer.OrdinalIgnoreCase);
   foreach(string key in new[]{"HF_HUB_DISABLE_TELEMETRY","HF_HUB_OFFLINE","HF_HUB_DISABLE_IMPLICIT_TOKEN","HF_DATASETS_OFFLINE","TRANSFORMERS_OFFLINE","DO_NOT_TRACK","PYTHONDONTWRITEBYTECODE"})env[key]="1";
   foreach(string key in new[]{"APPDATA","LOCALAPPDATA","USERPROFILE"})env[key]=privateDir;
   env["ALLUSERSPROFILE"]=Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);env["HF_HOME"]=Path.Combine(privateDir,"hf-cache");env["TEMP"]=env["TMP"]=Path.Combine(privateDir,"tmp");
   env["PATH"]=Path.Combine(root,"runtime-v2")+";"+Path.Combine(win,"System32");env["SystemRoot"]=env["WINDIR"]=win;env["SystemDrive"]=Path.GetPathRoot(win).TrimEnd('\\');env["TOKENIZERS_PARALLELISM"]="false";env["WANDB_DISABLED"]="true";env["LAYA_EXPECTED_SID"]=sidStr;
   var eb=new StringBuilder();foreach(var pair in env)eb.Append(pair.Key+"="+pair.Value+'\0');eb.Append('\0');ep=Marshal.StringToHGlobalUni(eb.ToString());
   SIX si=new SIX();si.si.cb=Marshal.SizeOf(typeof(SIX));si.attrs=attrs;
   // Suspended launch: no Python instruction runs before job assignment succeeds.
   if(!CreateProcessW(exe,cmd,IntPtr.Zero,IntPtr.Zero,false,0x00080000|0x00000400|0x08000000|0x4,ep,privateDir,ref si,out pi))throw new Exception("CREATE_PROCESS_FAILED: "+Marshal.GetLastWin32Error());
   if(!AssignProcessToJobObject(job,pi.process))throw new Exception("ISOLATION_JOB_ASSIGNMENT_FAILED: "+Marshal.GetLastWin32Error());
   if(ResumeThread(pi.thread)==0xffffffff)throw new Exception("RESUME_FAILED");
   Console.WriteLine("AppContainer child PID="+pi.pid+"; capabilities=0; job active-process limit=1; no inherited handles");
   if(WaitForSingleObject(pi.process,180000)!=0)throw new Exception("SYNTHETIC_TIMEOUT");
   uint code;if(!GetExitCodeProcess(pi.process,out code))throw new Exception("EXIT_CODE_UNAVAILABLE");completed=true;return (int)code;
  } catch(Exception e) {Console.Error.WriteLine(e.Message);return 1;}
  finally {
   if(pi.process!=IntPtr.Zero && !completed) {TerminateProcess(pi.process,124);WaitForSingleObject(pi.process,5000);}
   if(pi.thread!=IntPtr.Zero)CloseHandle(pi.thread);if(pi.process!=IntPtr.Zero)CloseHandle(pi.process);if(job!=IntPtr.Zero)CloseHandle(job);
   if(ep!=IntPtr.Zero)Marshal.FreeHGlobal(ep);if(attrReady)DeleteProcThreadAttributeList(attrs);if(attrs!=IntPtr.Zero)Marshal.FreeHGlobal(attrs);if(cp!=IntPtr.Zero)Marshal.FreeHGlobal(cp);if(sid!=IntPtr.Zero)FreeSid(sid);
  }
 }
}