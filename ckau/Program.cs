using HtmlAgilityPack;
using NetTools;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

public class QDPS
{
    private readonly Regex _hostnameRegex = new Regex(@"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$", RegexOptions.IgnoreCase);
    private string CIDRtoIPv4(uint ip) { return String.Format("{0}.{1}.{2}.{3}", ip >> 24, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff); }

    protected bool _addlocalip; // backing store for AddLocalIP; IP addresses from local network adapters are quickly added to _addressbag if this is true
    public bool AddLocalIP // gets or sets the value of _addlocalip
    {
        get { return _addlocalip; }
        set { _addlocalip = value; }
    }

    protected ConcurrentBag<IPAddress> _addressbag; // backing store for AddressBag; IP addresses to scan are added here after passing preliminary validation
    public ConcurrentBag<IPAddress> AddressBag // gets or sets the value of _addressbag
    {
        get { return _addressbag; }
        set { _addressbag = value; }
    }

    protected bool _force; // backing store for Force; bypass user prompts during execution if this is true
    public bool Force // gets or sets the value of _force
    {
        get { return _force; }
        set { _force = value; }
    }

    protected long _ignored; // backing store for Ignored; holds the number of duplicate and/or invalid IP addresses identified during preliminary validation
    public long Ignored // gets or sets the value of _ignored
    {
        get { return _ignored; }
        set { _ignored = value; }
    }

    protected List<ushort> _portlist; // backing store for Portlist; holds the list of ports to be scanned
    public List<ushort> Ports // gets or sets the value of _portlist
    {
        get { return _portlist; }
        set { _portlist = value; }
    }

    protected List<string> _serverargs; // backing store for ServerArgs; holds the list of validated command line arguments
    public List<string> ServerArgs // gets or sets the value of _serverargs
    {
        get { return _serverargs; }
        set { _serverargs = value; }
    }

    protected ushort _tick; // backing store for Sleep; holds the sleep interval in milliseconds
    public ushort Sleep // gets or sets the value of _tick
    {
        get { return _tick; }
        set
        {
            if (UInt16.TryParse(value.ToString(), out ushort t)) { _tick = t; } // user-specified value for _tick was valid
            else { _tick = 100; } // default value for _tick (supplied value was invalid)
        }
    }

    protected ushort _timeout; // backing store for Timeout; holds the timeout interval in milliseconds
    public ushort Timeout // gets or sets the value of _timeout
    {
        get { return _timeout; }
        set
        {
            if (UInt16.TryParse(value.ToString(), out ushort t)) { _timeout = t; } // user-specified value for _timeout was valid
            else { _timeout = 1000; } // default value for _timeout (supplied value was invalid)
        }
    }

    protected bool _verbose; // backing store for Verbose; verbose output is enabled if true
    public bool Verbose // gets or sets the value of _verbose
    {
        get { return _verbose; }
        set { _verbose = value; }
    }

    protected Stopwatch _validatetimer; // backing store for ValidateTimer; this is a stopwatch for timing the validation phase
    public Stopwatch ValidateTimer // gets or sets the value of _validatetimer
    {
        get { return _validatetimer; }
        set { _validatetimer = value; }
    }

    protected ConsoleColor _defaultfgcolor; // backing store for DefaultFGColor; this is the default foreground color for the active console window
    public ConsoleColor DefaultFGColor // gets/sets the value of _defaultfgcolor
    {
        get { return _defaultfgcolor; }
        set { _defaultfgcolor = value; }
    }

    public void Validate(string s) // validation method
    {
        try
        {
            if (string.IsNullOrWhiteSpace(s)) { throw new ArgumentException("Null or whitespace argument."); } // empty or null value supplied, ignore
            string[] cidr = s.Split('/', '-');
            if (IPAddress.TryParse(cidr[0], out IPAddress ip)) // valid IP address (range)
            {
                if (!s.Contains('/') && !s.Contains('-')) // single IP address
                {
                    if (_verbose)
                    {
                        Console.Write($"\r{" ",80}\r\t\t+  IP address : {ip}.\n\tCompiling list of addresses to scan  .  .  .", Console.ForegroundColor = _defaultfgcolor);
                        Console.ForegroundColor = ConsoleColor.DarkYellow;
                    }
                    _addressbag.Add(ip); // add this item to the address bag
                }
                else if (s.Contains('/')) // CIDR IP address range
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork && Convert.ToUInt16(cidr[1]) >= 0 && Convert.ToUInt16(cidr[1]) <= 32) // CIDR IPv4 address range
                    {
                        if (_verbose)
                        {
                            Console.Write($"\r{" ",80}\r\t\t+  IPv4 CIDR range : {s}.\n\tCompiling list of addresses to scan  .  .  .", Console.ForegroundColor = ConsoleColor.Cyan);
                            Console.ForegroundColor = ConsoleColor.DarkYellow;
                        }
                        string[] parts = s.Split('.', '/'); // store the address's octets and maskbits for conversion
                        uint ipnum = (Convert.ToUInt32(parts[0]) << 24) | (Convert.ToUInt32(parts[1]) << 16) | (Convert.ToUInt32(parts[2]) << 8) | Convert.ToUInt32(parts[3]);
                        int maskbits = Convert.ToInt32(parts[4]);
                        uint mask = 0xffffffff;
                        mask <<= (32 - maskbits); // number of addresses generated here will be 2 ^ (32 - maskbits), e.g. x.y.z.0/24 will generate 2 ^ (32 - 24) = 256 addresses
                        uint ipstart = ipnum & mask; // get the start of the range
                        uint ipend = ipnum | ~mask; // get the end of the range
                        IPAddress start = IPAddress.Parse(CIDRtoIPv4(ipstart)); // convert ipstart
                        IPAddress end = IPAddress.Parse(CIDRtoIPv4(ipend)); // convert ipend
                        IPAddressRange range = new IPAddressRange(start, end); // establish a range of addresses from start to end
                        Parallel.ForEach(range, (IPAddress ip) =>
                        {
                            _addressbag.Add(ip); // add this item to the address bag
                        });
                    }
                    else if (ip.AddressFamily == AddressFamily.InterNetworkV6 && Convert.ToUInt16(cidr[1]) >= 0 && Convert.ToUInt16(cidr[1]) <= 64) // CIDR IPv6 address range
                    {
                        if (_verbose)
                        {
                            Console.Write($"\r{" ",80}\r\t\t+  IPv6 CIDR range : {s}.\n\tCompiling list of addresses to scan  .  .  .", Console.ForegroundColor = ConsoleColor.Cyan);
                            Console.ForegroundColor = ConsoleColor.DarkYellow;
                        }
                    }
                    else { throw new ArgumentException($"Invalid IP address range : {s}."); } // bogus CIDR IP address range
                }
                else if (s.Contains('-')) // IP address range supplied as a.b.c.d - w.x.y.z
                {
                    if (!IPAddress.TryParse(cidr[1], out IPAddress ip2)) // a.b.c.d is a valid IP address, but w.x.y.z is not
                    {
                        if (_verbose)
                        {
                            Console.Write($"\r{" ",80}\r\t\t+  IP address : {ip}.\n\tCompiling list of addresses to scan  .  .  .", Console.ForegroundColor = ConsoleColor.Cyan);
                            Console.ForegroundColor = ConsoleColor.DarkYellow;
                        }
                        _addressbag.Add(ip); // add this item to the address bag
                    }
                    else if (ip.AddressFamily == AddressFamily.InterNetwork && ip2.AddressFamily == AddressFamily.InterNetwork) // IPv4 range
                    {
                        if (_verbose)
                        {
                            Console.Write($"\r{" ",80}\r\t\t+  IPv4 range : {s}.\n\tCompiling list of addresses to scan  .  .  .", Console.ForegroundColor = ConsoleColor.Cyan);
                            Console.ForegroundColor = ConsoleColor.DarkYellow;
                        }
                        string[] parts = s.Split('.', '-'); // store the address's octets and maskbits for conversion
                        uint abcd = (Convert.ToUInt32(parts[0]) << 24) | (Convert.ToUInt32(parts[1]) << 16) | (Convert.ToUInt32(parts[2]) << 8) | Convert.ToUInt32(parts[3]);
                        uint wxyz = (Convert.ToUInt32(parts[4]) << 24) | (Convert.ToUInt32(parts[5]) << 16) | (Convert.ToUInt32(parts[6]) << 8) | Convert.ToUInt32(parts[7]);
                        uint mask = 0xffffffff;
                        mask <<= (0); // 
                        uint ipstart = abcd & mask; // get the start of the range
                        uint ipend = wxyz & mask; // get the end of the range
                        IPAddress start = IPAddress.Parse(CIDRtoIPv4(ipstart)); // convert ipstart
                        IPAddress end = IPAddress.Parse(CIDRtoIPv4(ipend)); // convert ipend
                        IPAddressRange range = new IPAddressRange(start, end); // establish a range of addresses from start to end
                        Parallel.ForEach(range, (IPAddress ip) =>
                        {
                            _addressbag.Add(ip); // add this item to the address bag
                        });
                    }
                    else if (ip.AddressFamily == AddressFamily.InterNetworkV6 && ip2.AddressFamily == AddressFamily.InterNetworkV6) // IPv6 range
                    {
                        if (_verbose)
                        {
                            Console.Write($"\r{" ",80}\r\t\t+  IPv6 range : {s}.\n\tCompiling list of addresses to scan  .  .  .", Console.ForegroundColor = ConsoleColor.Cyan);
                            Console.ForegroundColor = ConsoleColor.DarkYellow;
                        }
                    }
                    else { throw new ArgumentException($"Invalid IP address range : {s}."); } // bogus IP address range
                } 
                else { throw new ArgumentException($"Invalid IP address (range) : {s}."); } // bogus IP address (range)
            }
            else if (_hostnameRegex.IsMatch(s)) // DNS hostname or single IP address
            {
                foreach (IPAddress a in Dns.GetHostAddresses(s)) // retrieve all IP addresses associated with this hostname
                {
                    if (_addressbag.Contains(a)) { _ignored++; } // ignore this item if is a duplicate or invalid
                    else
                    {
                        if (_verbose)
                        {
                            Console.Write($"\r{" ",80}\r\t\t+  IP address : {a} (DNS hostname : {s}).\n\tCompiling list of addresses to scan  .  .  .", Console.ForegroundColor = ConsoleColor.Cyan);
                            Console.ForegroundColor = ConsoleColor.DarkYellow;
                        }
                        _addressbag.Add(a); // add this IP address to the address bag
                    }
                }
            }
            else { throw new ArgumentException($"Invalid DNS hostname or IP address (range) : {s}."); } // strange things are afoot at the Circle K if we end up here
        }
        // caught exceptions should increment _ignored
        catch (ArgumentException) { _ignored++; }
        catch (SocketException) { _ignored++; }
    }

    protected List<IPAddress> _scanlist; // backing store for ScanList; holds the list of IP addresses to be scanned
    public List<IPAddress> ScanList // gets or sets the value of _scanlist
    {
        get { return _scanlist; }
        set { _scanlist = value; }
    }

    protected List<string> _onlinehosts; // backing store for OnlineHosts; holds the list of address:port values that are online
    public List<string> OnlineHosts // gets or sets the value of _onlinehosts
    {
        get { return _onlinehosts; }
        set { _onlinehosts = value; }
    }

    protected long _progresscounter; // backing store for the progress bar's counter object
    public long PBCounter // gets or sets the value of _progresscounter
    {
        get { return _progresscounter; }
        set { _progresscounter = value; }
    }

    protected long _progressmaximum; // backing store for the progress bar's maximum value
    public long PBMaximum // gets or sets the value of _progressmaximum
    {
        get { return _progressmaximum; }
        set { _progressmaximum = value; }
    }

    protected ProgressBar _progressbar; // backing store for the progress bar object
    public ProgressBar PB // gets or sets the value of _progressbar
    {
        get { return _progressbar; }
        set { _progressbar = value; }
    }

    protected Stopwatch _scantimer; // backing store for ScanTimer; this is a stopwatch for the scan phase
    public Stopwatch ScanTimer // gets or sets the value of _scantimer
    {
        get { return _scantimer; }
        set { _scantimer = value; }
    }

    public void Scan(IPAddress ipv4, int port) // scan method
    {
        _progressbar.Report((double)_progresscounter / _progressmaximum); // update the progress bar
        TcpClient scan = new TcpClient(); // new socket object
        try
        {
            scan.ConnectAsync(ipv4, port); // try to connect to port on ipv4
            for (int i = 0; i < _timeout; i += _tick) // give the connection attempt until timeout in slices of tick
            {
                Thread.Sleep(_tick); // sleep for a tick
                if (scan.Connected) // host is online and listening
                {
                    _onlinehosts.Add(ipv4.ToString() + ":" + port); // add this ipv4:port pair to the list of online hosts if it has not already been added
                    i = _timeout; // set the loop counter to the max timeout value to break the loop
                }
            }
            scan.Close(); // close the socket connection
            scan.Dispose(); // reclaim resources from the object
        }
        catch { }
        _progresscounter++; // increment the counter for the progress bar
    }

    public QDPS() // default new object constructor
    {
        _addlocalip = false; // quickly add IP addresses assigned to local network adapters
        _addressbag = new ConcurrentBag<IPAddress>(); // store for validated IP addresses; will likely contain duplicates
        _defaultfgcolor = Console.ForegroundColor; // get the active console window's foreground color
        _force = false; // bypass prompts for user input
        _ignored = 0; // this counter is incremented with each address identified as duplicate or invalid during validation
        _onlinehosts = new List<string>(); // online <IP address>:<port> pairs go here
        _portlist = new List<ushort>();  // port arguments that pass preliminary validation go here
        _progressbar = new ProgressBar(); // exactly what it says on the tin
        _scanlist = new List<IPAddress>(); // unique IP addresses from _addressbag go here
        _scantimer = new Stopwatch(); // timer for the scan phase
        _serverargs = new List<string>(); // server arguments that pass preliminary validation go here
        _tick = 10; // wait time in milliseconds before scan task status is polled for completion
        _timeout = 100; // time in milliseconds to wait before assuming a host or port is offline or closed
        _validatetimer = new Stopwatch(); // timer for the validation phase
        _verbose = false; // enable verbose output
    }
}

public class CKAU : QDPS
{
    protected bool _legacykeys; // backing store for LegacyKeys; keys for legacy and esoteric editions of Windows are included if true
    public bool LegacyKeys // gets or sets the value of _legacykeys
    {
        get { return _legacykeys; }
        set { _legacykeys = value; }
    }

    protected Dictionary<string, string> _validkeys; // backing store for ValidKeys; this is a table of valid edition(s) and matching KMS client setup key(s)
    public Dictionary<string, string> ValidKeys // gets or sets the value of _validkeys
    {
        get { return _validkeys; }
        set { _validkeys = value; }
    }

    protected Stopwatch _updategvlktimer; // backing store for UpdateGVLKTimer; this is a stopwatch for the update GVLK phase
    public Stopwatch UpdateGVLKTimer // gets or sets the value of _updategvlktimer
    {
        get { return _updategvlktimer; }
        set { _updategvlktimer = value; }
    }

    protected bool _updatekeys; // backing store for UpdateKeys; update local keys files if true
    public bool UpdateKeys // gets or sets the value of _updatekeys
    {
        get { return _updatekeys; }
        set { _updatekeys = value; }
    }

    protected bool _noscan; // backing store for NoScan; disable network scan if true
    public bool NoScan // gets or sets the value of _noscan
    {
        get { return _noscan; }
        set { _noscan = value; }
    }

    protected string _edition; // backing store for Edition; this is the OS caption of the installed or specified edition of Windows
    public string Edition // gets/sets the value of _edition
    {
        get { return _edition; }
        set { _edition = value; }
    }

    protected bool _addlocalsubnet; // backing store for AddLocalSubnet; if true, add the specified range of IP address(es) to the scan list
    public bool AddLocalSubnet // gets/sets the value of _addlocalsubnet
    {
        get { return _addlocalsubnet; }
        set { _addlocalsubnet = value; }
    }

    protected ushort _quickmask; // backing store for QuickMask; this is the mask value used to obtain the range of local IP address(es) to add to the scan list
    public ushort QuickMask // gets/sets the value of _quickmask
    {
        get { return _quickmask; }
        set { _quickmask = value; }
    }

    public CKAU() // default new object constructor
    {
        _addlocalsubnet = false; // quickly add a subnet to the scan list, using local IP addresses and _quickmask
        _edition = null; // version of Windows to activate
        _legacykeys = false; // include keys for legacy and esoteric editions of Windows
        _noscan = false; // if resultfile exists, disable network scan and add the contents of resultfile to the list of online hosts
        _quickmask = 24; // default mask for quick scan; this will yield a subnet of 256 IPv4 addresses
        _updategvlktimer = new Stopwatch(); // timer for the update GVLK phase
        _updatekeys = false; // update local keys files from the Internet
        _validkeys = new Dictionary<string, string>(); // supported edition(s) and matching KMS client setup key(s)
    }
}

public class Program
{
    // constants
    private const string SECTION_BREAK = "┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼"; // ewisott
    private const string PROGRAM_TITLE = "ckau - Console KMS Activation Utility"; // program window title
    private const string CKAU_FOLDER = ".ckau"; // folder for program data and output files
    private const string WINDOWS_GVLK_FILENAME = "windows.gvlk"; // local file containing public KMS client setup keys for current versions of Windows
    private const string WINDOWS_LEGACY_FILENAME = "windows-legacy.gvlk"; // local file containing KMS keys for legacy and esoteric versions of Windows
    private const string LOG_FILENAME = "ckau.log"; // program activity log
    private const string RESULT_FILENAME = "scan.results"; // online hosts as <address>:<port> from the last successful network scan

    // read-only variables
    private static readonly string defaultTitle = Console.Title; // the default window title
    private static readonly string homepath = $@"{Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)}"; // the full path to the user's profile folder
    private static readonly string ckaupath = Path.Combine(homepath, CKAU_FOLDER); // program output folder at ~/CKAU_FOLDER/
    private static readonly string gvlkfile = Path.Combine(ckaupath, WINDOWS_GVLK_FILENAME); // local store of edition/key pair(s) at ckaupath/WINDOWS_GVLK_FILENAME
    private static readonly string legacygvlkfile = Path.Combine(ckaupath, WINDOWS_LEGACY_FILENAME); // local store of edition/key pair(s) at ckaupath/WINDOWS_LEGACY_FILENAME
    private static readonly string logfile = Path.Combine(ckaupath, LOG_FILENAME); // log of program activity at ckaupath/LOG_FILENAME
    private static readonly string resultfile = Path.Combine(ckaupath, RESULT_FILENAME); // condensed list of most recent scan results at ckaupath/RESULT_FILENAME
    private static readonly Dictionary<string, string> validFlags = new Dictionary<string, string> // table of valid command line arguments with a brief description of each
    {
        { "-e", $"{"(--edition)",-18}The edition of Windows to be activated.\n{"",28}Specify a non-null, non-whitespace string for <edition>.\n{"",28}If omitted or invalid, <edition> defaults to the installed edition." },
        { "-f", $"{"(--force)",-18}Bypass any user prompt(s) to continue." },
        { "-l", $"{"(--local)",-18}Add localhost's IP address(es) to the scan list." },
        { "-L", $"{"(--legacykeys)",-18}Include keys from legacy and esoteric Windows editions." },
        { "-n", $"{"(--noscan)",-18}Disable network scan and refer to existing results file for valid online host(s).\n{"",28}Any value(s) specified for <ports> and/or <servers> will be ignored." },
        { "-p", $"{"(--ports)",-18}Port(s) to scan in a space-delineated list.\n{"",28}Specify one or more integer(s) X for <ports>; for each, 0 ≤ X ≤ 65535.\n{"",28}If omitted, <ports> defaults to 1688." },
        { "-q", $"{"(--quick)",-18}For each local IPv4 address, add <address>/<mask> to the scan list; implies -l.\n{"",28}Specify an integer X for <mask>, where 0 ≤ X ≤ 32 (default : 24)." },
        { "-s", $"{"(--servers)",-18}Server(s) to scan in a space-delineated list.\n{"",28}Specify one or more of the following for <servers> :\n{"",30}(1) a DNS hostname or IP address.\n{"",30}(2) a range of IPv4 addresses as a.b.c.d/xx.\n{"",30}(3) a range of IPv4 addresses as a.b.c.d-w.x.y.z." },
        { "-S", $"{"(--sleep)",-18}Time to wait in milliseconds before querying status of individual scan(s).\n{"",28}Specify an integer X for <tick>, where 10 ≤ X ≤ 65535 (default : 10)." },
        { "-t", $"{"(--timeout)",-18}Time to wait in milliseconds before automatically cancelling individual scan(s).\n{"",28}Specify an integer X for <timeout>, where 10 ≤ X ≤ 65535 (default : 100)." },
        { "-U", $"{"(--updatekeys)",-18}Update the local keys files from the Internet." },
        { "-v", $"{"(--verbose)",-18}Display comprehensive program output." },
        { "-V", $"{"(--validkeys)",-18}Display supported edition(s) and matching KMS client setup key(s)." },
        { "-?", $"{"(-h, --help)",-18}Display this help screen, or display detailed help for (all) <argument>(s)." }
    }; // end of validFlags

    // task (factory) controls
    private static CancellationTokenSource cts = new CancellationTokenSource(); // the source for the task factory's cancellation token
    private static readonly TaskFactory factory = new TaskFactory(cts.Token); // a task factory with a custom cancellation token
    private static ConcurrentBag<Task> taskbag = new ConcurrentBag<Task>(); // tasks go here to await further processing

    // program control object
    private static readonly CKAU ckau = new CKAU();

    static async Task Main(string[] args)
    {
        Console.WriteLine($"\n\t{PROGRAM_TITLE}");
        try
        {
            // argument validation
            if (args.Length == 0 || (args.Length == 1 && (args.Contains("-h") || args.Contains("--help") || args.Contains("-?")))) // supplied arguments contain one or more of the defined "show help" flag(s), or there are no arguments
            {
                ShowHelp(null); // display the generic built-in help
                return; // terminate now
            }
            if (args.Length == 2 && (args.Contains("-h") || args.Contains("--help") || args.Contains("-?"))) // two arguments : detailed help for one or more argument(s)
            {
                if (args.Contains("all")) { ShowHelp("all"); } // display detailed help for all arguments
                // display detailed help for specific arguments
                else if (args.Contains("-e") || args.Contains("--edition")) { ShowHelp("-e"); }
                else if (args.Contains("-f") || args.Contains("--force")) { ShowHelp("-f"); }
                else if (args.Contains("-l") || args.Contains("--local")) { ShowHelp("-l"); }
                else if (args.Contains("-L") || args.Contains("--legacykeys")) { ShowHelp("-L"); }
                else if (args.Contains("-n") || args.Contains("--noscan")) { ShowHelp("-n"); }
                else if (args.Contains("-p") || args.Contains("--ports")) { ShowHelp("-p"); }
                else if (args.Contains("-q") || args.Contains("--quick")) { ShowHelp("-q"); }
                else if (args.Contains("-s") || args.Contains("--servers")) { ShowHelp("-s"); }
                else if (args.Contains("-S") || args.Contains("--sleep")) { ShowHelp("-S"); }
                else if (args.Contains("-t") || args.Contains("--timeout")) { ShowHelp("-t"); }
                else if (args.Contains("-U") || args.Contains("--updatekeys")) { ShowHelp("-U"); }
                else if (args.Contains("-v") || args.Contains("--verbose")) { ShowHelp("-v"); }
                else if (args.Contains("-V") || args.Contains("--validkeys")) { ShowHelp("-V"); }
                else { ShowHelp(null); } // display generic help
                return; // terminate now
            }
            if (args.Contains("-L") || args.Contains("--legacykeys")) { ckau.LegacyKeys = true; } // include keys for legacy and esoteric editions of Windows
            if (args.Contains("-U") || args.Contains("--updatekeys")) { ckau.UpdateKeys = true; } // update local keys files
            if (args.Contains("-V") || args.Contains("--validkeys")) // supplied arguments contain one or more of the defined "show valid keys" flag(s)
            {
                ckau.Verbose = true; // force verbose output here, or very little will be displayed
                GetWindowsGVLK(); // retrieve and display the specified supported edition/key pairs
                return; // terminate now
            }
            if (args.Length > 0) // if we made it here, the supplied arguments count is non-zero, and none of the "show help" or "show valid keys" flag(s) are present
            {
                Console.Title = PROGRAM_TITLE; // set the active console window title
                if (!Directory.Exists(ckaupath)) Directory.CreateDirectory(ckaupath); // create the output folder if it does not exist
                Console.Write($"  {SECTION_BREAK}\n\tValidating supplied parameter(s)  .  .  .", Console.ForegroundColor = ckau.DefaultFGColor);
                if (args.Contains("-f") || args.Contains("--force")) { ckau.Force = true; } // bypass user prompts
                if (args.Contains("-n") || args.Contains("--noscan")) { ckau.NoScan = true; } // disable network scan
                if (args.Contains("-l") || args.Contains("--local")) { ckau.AddLocalIP = true; } // quick-scan local IP addresses
                if (args.Contains("-v") || args.Contains("--verbose")) { ckau.Verbose = true; } // enable verbose output
                for (int i = 0; i < args.Length; i++) // parse remaining arguments; these are complex arguments
                {
                    int j = i + 1; // one ahead of the current argument
                    if (args[i].Equals("-f") || args[i].Equals("--force")
                        || args[i].Equals("-l") || args[i].Equals("--local")
                        || args[i].Equals("-L") || args[i].Equals("--legacykeys")
                        || args[i].Equals("-n") || args[i].Equals("--noscan")
                        || args[i].Equals("-U") || args[i].Equals("--updatekeys")
                        || args[i].Equals("-v") || args[i].Equals("--verbose")) { } // these flags should have already been processed above, so do nothing
                    else if ((args[i].Equals("-e") || args[i].Equals("--edition")) && !string.IsNullOrWhiteSpace(args[j])) ckau.Edition = args[j]; // the edition to activate
                    else if (args[i].Equals("-p") || args[i].Equals("--ports")) // one or more ports to scan
                    {
                        for (j = i + 1; j < args.Length; j++) // process any arguments following this switch
                        {
                            if (j == args.Length) { } // this is the final argument, so do nothing
                            else if (args[j].StartsWith("-")) j = args.Length; // this argument is another switch, so break the loop and otherwise do nothing
                            else if (UInt16.TryParse(args[j], out ushort p) && !ckau.Ports.Contains(p)) { ckau.Ports.Add(p); } // validate and add this argument to list
                            else { } // this argument is not a valid port, so do nothing
                        }
                    }
                    else if (args[i].Equals("-q") || args[i].Equals("--quick")) // quick-scan a range of IP addresses derived from localhost's addresses
                    {
                        ckau.AddLocalSubnet = true;
                        if (j == args.Length) { ckau.QuickMask = 24; } // this is the final argument, so set the mask to the default value
                        else if (args[j].StartsWith("-")) { ckau.QuickMask = 24; } // the next argument is a switch, so set the mask to the default value
                        else if (UInt16.TryParse(args[j], out ushort m) && m <= 32) { ckau.QuickMask = m; } // set the mask to the specified value
                        else { ckau.QuickMask = 24; } // set the mask to the default value
                    }
                    else if (args[i].Equals("-s") || args[i].Equals("--servers")) // one or more servers to scan
                    {
                        for (j = i + 1; j < args.Length; j++) // process any arguments following this switch
                        {
                            if (j == args.Length) { } // this is the final argument, so do nothing
                            else if (args[j].StartsWith("-")) j = args.Length; // this argument is another switch, so break the loop and otherwise do nothing
                            else if (IsValidHostnameOrIPAddress(args[j]) && !ckau.ServerArgs.Contains(args[j])) { ckau.ServerArgs.Add(args[j]); } // validate and add this argument to list
                            else { } // this argument is not a valid IP address or hostname, so do nothing
                        }
                    }
                    else if ((args[i].Equals("-S") || args[i].Equals("--sleep")) && UInt16.TryParse(args[j], out ushort u) && u >= 10) { ckau.Sleep = u; } // sleep/tick value
                    else if ((args[i].Equals("-t") || args[i].Equals("--timeout")) && UInt16.TryParse(args[j], out ushort t) && t >= 10) { ckau.Timeout = t; } // max timeout value
                    else { } // invalid switch and/or argument; ignore
                }
            }
            else { } // strange things are afoot at the Circle K if we end up here
            if (!ckau.NoScan) // perform a QDPS here, except if -n or --noscan was supplied on the command line
            {
                if (ckau.AddLocalIP || ckau.AddLocalSubnet) { GetLocalIP(); }
                if (ckau.Ports.Count == 0) ckau.Ports.Add(1688); // add a default port to scan to the list if none were provided on the command line
                if (ckau.Verbose)
                {
                    Console.Write("\n");
                    foreach (ushort port in ckau.Ports) Console.WriteLine($"\t\t+  Port : {port}", Console.ForegroundColor = ConsoleColor.Cyan); // verbose console output
                }
                await GetOnlineHosts(); // process and validate server arguments to generate the list of addresses to scan
                if (!ckau.Force) // user prompt; bypass if -f or --force was passed as an argument
                {
                    Console.Write($"\n\tPreparation complete. Press 'Y' to proceed with network scan; press any other key to abort : "); // prompt for user input
                    char key = Console.ReadKey().KeyChar; // wait for user input
                    if (key != 'y' && key != 'Y') throw new OperationCanceledException("Operation canceled by user."); // terminate if the key pressed is not an upper- or lowercase 'Y'
                    Console.Write("\n");
                }
                await ScanIndicatedHosts(); // scan every validated port on each address in the scan list
            }
            else if (ckau.NoScan) // disable network scan and use existing results file
            {
                if (!File.Exists(resultfile) || string.IsNullOrWhiteSpace(File.ReadAllText(resultfile))) // if the file doesn't exist or is empty, network scan
                {
                    if (ckau.AddLocalIP || ckau.AddLocalSubnet) { GetLocalIP(); }
                    if (ckau.Ports.Count == 0) ckau.Ports.Add(1688); // add a default port to scan to the list if none were provided on the command line
                    if (ckau.Verbose)
                    {
                        Console.Write("\n");
                        foreach (ushort port in ckau.Ports) Console.WriteLine($"\t\t+  Port : {port}", Console.ForegroundColor = ConsoleColor.Cyan); // verbose console output
                    }
                    await GetOnlineHosts(); // process and validate server arguments to generate the list of addresses to scan
                    if (!ckau.Force) // user prompt; bypass if -f or --force was passed as an argument
                    {
                        Console.Write($"\n\tPreparation complete. Press 'Y' to proceed with network scan; press any other key to abort : "); // prompt for user input
                        char key = Console.ReadKey().KeyChar; // wait for user input
                        if (key != 'y' && key != 'Y') throw new OperationCanceledException("Operation canceled by user."); // terminate if the key pressed is not an upper- or lowercase 'Y'
                        Console.Write("\n");
                    }
                    await ScanIndicatedHosts(); // scan every validated port on each address in the scan list
                }
                else if (File.Exists(resultfile) && !string.IsNullOrWhiteSpace(File.ReadAllText(resultfile)))
                {
                    using StreamReader r = File.OpenText(resultfile); // the file to read from; should be CSV
                    string line;
                    while ((line = r.ReadLine()) != null) // iterate over each line of the file until an empty line is found
                    {
                        if (!ckau.OnlineHosts.Contains(line)) ckau.OnlineHosts.Add(line); // add the edition/key pair to the internal dictionary
                    }
                    r.Close(); // close the file and reclaim resources from the StreamReader object
                    Console.Write($"  [DONE!]\n", Console.ForegroundColor = ConsoleColor.Green);
                    Cleanup(); // reclaim resources from the token source and progress bar
                }
                else { throw new ApplicationException($"An unrecognized error occurred involving {resultfile}."); } // strange things are afoot at the Circle K if we end up here
            }
            else { } // strange things are afoot at the Circle K if we end up here
            GetWindowsGVLK(); // import supported Windows edition/key pairs here
            if (ckau.Edition == null || !ckau.ValidKeys.ContainsKey(ckau.Edition)) ckau.Edition = GetWindowsEdition(); // get the installed Windows edition if (an invalid) one was (not) specified on the command line
            Console.WriteLine($"\tInstalled or specified edition of Windows : {ckau.Edition}");
            string osKey = ckau.ValidKeys[ckau.Edition]; // get the KMS setup key for the installed or specified edition
            Console.WriteLine($"\tPublic KMS client setup key for this edition : {osKey}");
            if (!ckau.Force) // user prompt; bypass if -f or --force was passed as an argument
            {
                Console.Write($"\n\tReady to activate. Press 'Y' to proceed with activation; press any other key to abort : "); // prompt for user input
                char key = Console.ReadKey().KeyChar; // wait for user input
                if (key != 'y' && key != 'Y') throw new OperationCanceledException("Operation canceled by user."); // terminate if the key pressed is not an upper- or lowercase 'Y'
                Console.Write("\n");
            }
            ActivateWindows(osKey); // use SLMGR to activate Windows with the specified key
            using StreamWriter w = File.AppendText(logfile); // prepare the log file
            LogScanResults(w); // append to the log file before terminating
        }
        catch (OperationCanceledException exc) // cancelled by user
        {
            Console.Write($"\n\t[WARNING]", Console.ForegroundColor = ConsoleColor.DarkYellow);
            Console.Write($" : {exc.Message}\n\n", Console.ForegroundColor = ckau.DefaultFGColor);
        }
        catch (ApplicationException exc) // thrown application exception
        {
            Console.Write($"\n\t[ERROR]", Console.ForegroundColor = ConsoleColor.Red);
            Console.Write($" : {exc.Message}\n\n", Console.ForegroundColor = ckau.DefaultFGColor);
        }
        catch (Exception exc) // unknown error
        {
            Console.Write($"\n\t[ERROR]", Console.ForegroundColor = ConsoleColor.Red);
            Console.Write($" : {exc.Message}\n\n", Console.ForegroundColor = ckau.DefaultFGColor);
        }
        finally // cleanup before terminating
        { 
            Console.Title = defaultTitle;
        }
    }

    static void ShowHelp(string s) // display brief or detailed help
    {
        Console.WriteLine($"\n{"Usage",10} : ckau.exe [-e <edition>] [-f] [-l] [-L] [-n] [-p <ports>] [-q <mask>]\n\t\t\t[-s <servers>] [-S <tick>] [-t <timeout>] [-U] [-v]");
        Console.WriteLine($"{"ckau.exe",21} -V [-L] [-U]\n{"ckau.exe",21} -? [all] [<argument>]\n  {SECTION_BREAK}");
        if (s == "all") { foreach ((string flag, string desc) in validFlags) { Console.WriteLine($"{flag,7} {desc}"); } } // display help for all arguments
        else if (string.IsNullOrWhiteSpace(s)) { Console.WriteLine($"{"-?",7} {validFlags["-?"]}"); } // display help for the help arguments
        else { Console.WriteLine($"{s,7} {validFlags[s]}"); } // display help for this argument
        Console.WriteLine($"  {SECTION_BREAK}\n{"",5}Program data and output files are located at  ~/.ckau\n{"",5}See  ~/.ckau/README.MD  for comprehensive help and other details.\n");
    }

    static void Cleanup() { cts.Dispose(); ckau.PB.Dispose(); } // dispose of the token source and progress bar

    static void LogScanResults(TextWriter w)
    {
        string scanDivider = "─────────────────────────────────────────────────────────────────────────────────────";
        Console.Write($"\tLogging results  .  .  .  ");
        w.Write($"\r\n {scanDivider}\n");
        w.Write(" QDPS scan results : ");
        w.WriteLine($"{DateTime.Now.ToLongTimeString()} {DateTime.Now.ToLongDateString()}");
        w.Write($" Supplied input parameter(s)");
        w.Write($"\n   * {"Port(s)"} ({ckau.Ports.Count}) :");
        foreach (int port in ckau.Ports) w.Write($"   {port}"); // log each port input parameter
        w.Write($"\n   * {"Server(s)"} ({ckau.ServerArgs.Count}) :");
        foreach (string server in ckau.ServerArgs) w.Write($"   {server}"); // log each address/hostname input parameter
        w.Write($"\n   * {"Timeout"} :   {ckau.Timeout}/{ckau.Sleep} ms");
        w.Write($"\n   * {"Local IP"} :   {ckau.AddLocalIP}");
        w.Write($"\n   * {"Verbose"} :   {ckau.Verbose}");
        w.WriteLine($"\n Scanned   {ckau.Ports.Count}   port(s) on   {ckau.ScanList.Count}   of   {ckau.AddressBag.Count}   address(es)   [ {ckau.Ports.Count * ckau.ScanList.Count} total scan(s) ]");
        foreach (string host in ckau.OnlineHosts) w.WriteLine($"   + {host}"); // log each online host as address:port
        w.WriteLine($" Found   {ckau.OnlineHosts.Count}   online host(s) in   {Math.Round(ckau.ScanTimer.Elapsed.TotalSeconds, 3)}   seconds.");
        w.WriteLine($" {scanDivider}");
        Console.Write($"[DONE!]\n\n", Console.ForegroundColor = ConsoleColor.Green);
        Console.ResetColor();
    }

    static void GetLocalIP() // poll local network adapters and obtain their IP address(es)
    {
        NetworkInterface.GetAllNetworkInterfaces().ToList().ForEach(ni =>
        {
            if (ni.GetIPProperties().GatewayAddresses.FirstOrDefault() != null)
            {
                ni.GetIPProperties().UnicastAddresses.ToList().ForEach(ua =>
                {
                    if (IPAddress.TryParse(ua.Address.ToString(), out IPAddress ip))
                    {
                        if (ip.AddressFamily == AddressFamily.InterNetwork) // IPv4 address (range)
                        {
                            if (ckau.AddLocalSubnet) { ckau.ServerArgs.Add($"{ip}/{ckau.QuickMask}"); } // quick-scan local subnet
                            else if (ckau.AddLocalIP) { ckau.ServerArgs.Add($"{ip}"); } // quick-scan local address
                            else { throw new ArgumentException($"AddLocalIP and AddLocalSubnet are both false, so we shouldn't even be here."); } // strange things are afoot at the Circle K if we end up here
                        }
                        else if (ip.AddressFamily == AddressFamily.InterNetworkV6) // IPv6 address (range)
                        {
                            // stub
                        }
                        else { } // loopback or other address which we don't care about
                    }
                });
            }
        });
    }

    static bool IsValidHostnameOrIPAddress(string a)
    {
        string[] parts = a.Split('/', '-');
        Regex validHostnameRegex = new Regex(@"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$", RegexOptions.IgnoreCase);
        try
        {
            if (string.IsNullOrWhiteSpace(a)) return false;
            else if (validHostnameRegex.IsMatch(parts[0].Trim())) return true;
            else if (IPAddress.TryParse(parts[0], out IPAddress ip) && (ip.AddressFamily == AddressFamily.InterNetwork || ip.AddressFamily == AddressFamily.InterNetworkV6)) return true;
            else return false;
        }
        catch { return false; }
    }

    public static async Task GetOnlineHosts()
    {
        Console.ForegroundColor = ConsoleColor.DarkYellow;
        ckau.ValidateTimer.Start();
        Parallel.ForEach(ckau.ServerArgs, (string s) => // spin tasks to validate the supplied addresses here
        {
            taskbag.Add(factory.StartNew(() => { ckau.Validate(s); })); // GenerateAddressList(s); })); // spin a task and add it to the task bag
        });
        try { await Task.WhenAll(taskbag.ToArray()); } // wait for all running tasks to complete
        catch (OperationCanceledException) { Console.WriteLine($"\n{nameof(OperationCanceledException)} thrown\n"); }
        finally { Cleanup(); ckau.ScanList = ckau.AddressBag.Distinct().ToList(); ckau.Ignored += ckau.AddressBag.Count - ckau.ScanList.Count; } // reclaim resources from the token source and progress bar, and filter the address bag
        ckau.ValidateTimer.Stop();
        Console.Write($"  [DONE!]\n", Console.ForegroundColor = ConsoleColor.Green);
        if (ckau.Verbose && ckau.Ignored > 0) 
        { 
            Console.Write($"\tIgnoring   ", Console.ForegroundColor = ConsoleColor.Cyan);
            Console.Write($"{ckau.Ignored}", Console.ForegroundColor = ConsoleColor.DarkYellow);
            Console.Write($"   duplicate or invalid item(s).\n", Console.ForegroundColor = ConsoleColor.Cyan);
        }
        Console.Write($"\tFound   ", Console.ForegroundColor = ckau.DefaultFGColor);
        Console.Write($"{ckau.ScanList.Count}", Console.ForegroundColor = ConsoleColor.Cyan);
        Console.Write($"   unique address(es) from   ", Console.ForegroundColor = ckau.DefaultFGColor);
        Console.Write($"{ckau.AddressBag.Count}", Console.ForegroundColor = ConsoleColor.Cyan);
        Console.Write($"   total in   ", Console.ForegroundColor = ckau.DefaultFGColor);
        Console.Write($"{Math.Round(ckau.ValidateTimer.Elapsed.TotalSeconds, 6)}", Console.ForegroundColor = ConsoleColor.DarkYellow);
        Console.Write($"   seconds.\n", Console.ForegroundColor = ckau.DefaultFGColor);
    }

    public static async Task ScanIndicatedHosts()
    {
        Console.Write($"  {SECTION_BREAK}\n\tScanning   ", Console.ForegroundColor = ckau.DefaultFGColor);
        Console.Write($"{ckau.Ports.Count}", Console.ForegroundColor = ConsoleColor.DarkCyan);
        Console.Write($"   port(s) on   ", Console.ForegroundColor = ckau.DefaultFGColor);
        Console.Write($"{ckau.ScanList.Count}", Console.ForegroundColor = ConsoleColor.DarkCyan);
        Console.Write($"   address(es)   [ ", Console.ForegroundColor = ckau.DefaultFGColor);
        Console.Write($"{ckau.Ports.Count * ckau.ScanList.Count}", Console.ForegroundColor = ConsoleColor.Yellow);
        Console.Write($" total scan(s) ]  .  .  .  ", Console.ForegroundColor = ckau.DefaultFGColor);
        Console.ForegroundColor = ConsoleColor.DarkYellow;
        taskbag = new ConcurrentBag<Task>(); // clear the task bag
        ckau.PB = new ProgressBar(); // reset the inline progress bar
        ckau.PBCounter = 0; // reset the counter for the progress bar
        ckau.PBMaximum = ckau.Ports.Count * ckau.ScanList.Count; // define the upper limit of the progress bar
        ckau.ScanTimer.Start(); // begin timing
        Parallel.ForEach(ckau.ScanList, (IPAddress ip) => // parse the scan list
        {
            Parallel.ForEach(ckau.Ports, (ushort port) => // parse the ports list
            {
                cts = new CancellationTokenSource(ckau.Timeout); // create a new auto-cancelling token source for each new task
                Task task = factory.StartNew(() => ckau.Scan(ip, port)); // spin a new task to scan this address:port pair
                taskbag.Add(task); // add this task to the task bag
                Thread.Sleep(ckau.Sleep / 10); // pause for a fraction of a tick
            });
        });
        try { await Task.WhenAll(taskbag.ToArray()); } // wait for all running tasks to complete
        catch (OperationCanceledException) { Console.WriteLine($"\n{nameof(OperationCanceledException)} thrown\n"); }
        finally { Cleanup(); } // reclaim resources from the token source and progress bar
        ckau.ScanTimer.Stop(); // end timing
        Console.Write($"[DONE!]\n", Console.ForegroundColor = ConsoleColor.Green);
        if (File.Exists(resultfile)) File.Delete(resultfile); // overwrite resultfile if it exists
        using StreamWriter w = File.AppendText(resultfile);
        foreach (string host in ckau.OnlineHosts)
        {
            w.WriteLine(host); // write this item to the result file
            if (ckau.Verbose) Console.WriteLine($"\t\t+  {host}", Console.ForegroundColor = ConsoleColor.Cyan); // verbose console output
        }
        Console.Write($"\tFound   ", Console.ForegroundColor = ckau.DefaultFGColor);
        Console.Write($"{ckau.OnlineHosts.Count}", Console.ForegroundColor = ConsoleColor.Cyan);
        Console.Write($"   online host(s) in   ", Console.ForegroundColor = ckau.DefaultFGColor);
        Console.Write($"{Math.Round(ckau.ScanTimer.Elapsed.TotalSeconds, 6)}", Console.ForegroundColor = ConsoleColor.DarkYellow);
        Console.Write($"   seconds.\n  {SECTION_BREAK}\n", Console.ForegroundColor = ckau.DefaultFGColor);
    }

    public static string GetWindowsEdition()
    {
        string osCaption = null; // initialize the OS caption store
        var moSearch = new ManagementObjectSearcher("SELECT Caption FROM Win32_OperatingSystem"); // query WMI to obtain the OS caption
        var moCollection = moSearch.Get(); // retrieve the results of the query
        foreach (ManagementObject mo in moCollection) osCaption = mo["Caption"].ToString(); // iterate over the results and store the OS caption
        string result = osCaption.Replace("Microsoft ", ""); // trim the OS caption
        return result;
    }

    public static void GetWindowsGVLK()
    {
        Console.Write($"\tGenerating table of supported edition(s) and matching KMS client setup key(s)  .  .  .", Console.ForegroundColor = ckau.DefaultFGColor);
        ckau.UpdateGVLKTimer.Start();
        if (!File.Exists(gvlkfile) || ckau.UpdateKeys) // download needed data and store it in a file for next time
        {
            if (File.Exists(gvlkfile)) { File.Delete(gvlkfile); Thread.Sleep(ckau.Sleep); }
            var url = "https://docs.microsoft.com/en-us/windows-server/get-started/kmsclientkeys"; // public KMS client setup keys for current editions are located here
            var web = new HtmlWeb();
            var doc = web.Load(url); // retrieve url and store the html here
            HtmlNode[] nodes = doc.DocumentNode.SelectNodes("//td").ToArray(); // isolate the table data from the downloaded data
            using StreamWriter w = File.AppendText(gvlkfile); // the file to write to
            for (int i = 0; i < nodes.Length; i++)
            {
                string nodeText = nodes[i].InnerHtml; // store for the edition text we're searching for
                if (nodeText.StartsWith("Windows 10") // current desktop version
                    || nodeText.StartsWith("Windows Server 2019")) // current server version
                {
                    string key = nodes[i + 1].InnerHtml; // this should be the key that corresponds to the matched edition
                    if (!key.Contains("?????")) w.WriteLine($"{nodeText},{key}"); // write the edition/key pair to the file
                }
            }
        }
        if (!File.Exists(legacygvlkfile) || ckau.UpdateKeys) // download needed data and store it in a file for next time
        {
            if (File.Exists(legacygvlkfile)) { File.Delete(legacygvlkfile); Thread.Sleep(ckau.Sleep); }
            var url = "https://py-kms.readthedocs.io/en/latest/Keys.html"; // public KMS client setup keys for legacy and esoteric editions are located here
            var web = new HtmlWeb();
            var doc = web.Load(url);
            HtmlNode[] nodes = doc.DocumentNode.SelectNodes("//td").ToArray(); // isolate the table data from the downloaded data
            using StreamWriter w = File.AppendText(legacygvlkfile); // the file to write to
            for (int i = 0; i < nodes.Length; i++)
            {
                string nodeText = nodes[i].InnerHtml; // store for the edition text we're searching for
                if (nodeText.StartsWith("Windows 8.1") || nodeText.StartsWith("Windows 8") || nodeText.StartsWith("Windows 7") || nodeText.StartsWith("Windows Vista")
                    || nodeText.StartsWith("Windows Server 2016") || nodeText.StartsWith("Windows Server 2012") || nodeText.StartsWith("Windows Server 2008"))
                {
                    string key = nodes[i + 1].InnerHtml.Replace("<code>", "").Replace("</code>", "").Replace("<br>", "").Substring(0, 29); // this should be the key(s) that corresponds to the matched edition; remove any cruft so that a single key remains
                    if (!key.Contains("?????")) w.WriteLine($"{nodeText},{key}"); // write the edition/key pair to the file
                }
            }
        }
        if (!File.Exists(gvlkfile)) { throw new FileNotFoundException($"{WINDOWS_GVLK_FILENAME} not found in the expected location at {ckaupath}."); } // throw an error here if the gvlk file does not exist at this point
        using StreamReader r = File.OpenText(gvlkfile); // the file to read from; should be CSV
        string line;
        while ((line = r.ReadLine()) != null) // iterate over each line of the file until an empty line is found
        {
            string[] parts = line.Split(','); // edition on the left, key on the right
            if (!ckau.ValidKeys.ContainsKey(parts[0]) && !parts[1].Contains("?????")) ckau.ValidKeys.Add(parts[0], parts[1]); // add the edition/key pair to the internal dictionary
        }
        r.Close();
        if (ckau.LegacyKeys) // include legacy editions and keys
        {
            if (!File.Exists(legacygvlkfile)) { throw new FileNotFoundException($"{WINDOWS_LEGACY_FILENAME} not found in the expected location at {ckaupath}."); } // throw an error here if the gvlk file does not exist at this point
            using StreamReader legacy = File.OpenText(legacygvlkfile); // the file to read from; should be CSV
            while ((line = legacy.ReadLine()) != null) // iterate over each line of the file until an empty line is found
            {
                string[] parts = line.Split(','); // edition on the left, key on the right
                if (!ckau.ValidKeys.ContainsKey(parts[0]) && !parts[1].Contains("?????")) ckau.ValidKeys.Add(parts[0], parts[1]); // add the edition/key pair to the internal dictionary
            }
            legacy.Close();
        }
        ckau.UpdateGVLKTimer.Stop();
        Console.Write($"  [DONE!]\n", Console.ForegroundColor = ConsoleColor.Green);
        if (ckau.Verbose) foreach ((string key, string value) in ckau.ValidKeys) Console.WriteLine($"\t\t+{value,31}  -  {key}", Console.ForegroundColor = ConsoleColor.Cyan);
        Console.Write($"\tImported   ", Console.ForegroundColor = ckau.DefaultFGColor);
        Console.Write($"{ckau.ValidKeys.Count}", Console.ForegroundColor = ConsoleColor.Cyan);
        Console.Write($"   valid edition/key pair(s) in   ", Console.ForegroundColor = ckau.DefaultFGColor);
        Console.Write($"{Math.Round(ckau.UpdateGVLKTimer.Elapsed.TotalSeconds, 6)}", Console.ForegroundColor = ConsoleColor.DarkYellow);
        Console.Write($"   seconds.\n  {SECTION_BREAK}\n", Console.ForegroundColor = ckau.DefaultFGColor);
    }

    public static string SLMGR(string args, string outMsg, string match, string errMsg)
    {
        Console.Write($"\t{outMsg}  .  .  .  ");
        Process vbsProcess = new Process();
        vbsProcess.StartInfo.FileName = @"cscript.exe";
        vbsProcess.StartInfo.WorkingDirectory = @"C:\Windows\System32\";
        vbsProcess.StartInfo.Arguments = $"//nologo slmgr.vbs {args}";
        vbsProcess.StartInfo.RedirectStandardOutput = true; // suppress process output
        vbsProcess.Start();
        string vbsOutput = vbsProcess.StandardOutput.ReadToEnd(); // store process output
        vbsProcess.WaitForExit();
        vbsProcess.Close();
        if (vbsOutput.Contains(match))
        {
            Console.Write("[DONE!]\n", Console.ForegroundColor = ConsoleColor.Green);
            Console.ResetColor();
            return vbsOutput;
        }
        else if (!vbsOutput.Contains(match) && args == "/ato") { return vbsOutput; }
        else Console.Write("[FAIL!]\n", Console.ForegroundColor = ConsoleColor.Red);
        Console.ResetColor();
        throw new ApplicationException(errMsg); // match is not present in the output stream
    }

    public static void ActivateWindows(string gvlk)
    {
        Console.Write($"  {SECTION_BREAK}\n", Console.ForegroundColor = ckau.DefaultFGColor);
        string slmgrOutput = null; // initialize slmgr.vbs output stream store
        slmgrOutput = SLMGR("/dli", "Obtaining current license status", "License Status", "slmgr.vbs /dli : Unknown error."); // obtain the current license status
        slmgrOutput = SLMGR("/upk", "Uninstalling existing product key(s)", "successfully", "slmgr.vbs /upk : Failed to uninstall existing product key."); // remove any existing license key(s)
        slmgrOutput = SLMGR("/cpky", "Removing existing product key(s) from the registry", "successfully", "slmgr.vbs /cpky : Unable to remove existing product key from registry."); // delete any existing license key(s) from the registry
        slmgrOutput = SLMGR($"/ipk {gvlk}", "Installing specified KMS client setup key(s)", "successfully", "slmgr.vbs /ipk : Unable to install specified KMS client setup key."); // install the specified license key(s)
        int attempts = 1; // initialize the attempts counter
        foreach (string host in ckau.OnlineHosts)
        {
            string attMsg = $"Setting KMS host server [{attempts} of {ckau.OnlineHosts.Count}]";
            string[] parts = host.Split(":");
            slmgrOutput = SLMGR($"/skms {parts[0]}:{parts[1]}", attMsg, "successfully", "slmgr.vbs /skms error."); // set the KMS server to activate against
            slmgrOutput = SLMGR("/ato", "Attempting to activate Windows", "successfully", "slmgr.vbs /ato : Unable to activate against the specified KMS server."); // attempt to activate
            if (!slmgrOutput.Contains("successfully.") && attempts != ckau.OnlineHosts.Count)
            {
                Console.Write("\r");
                attempts++;
            }
            else if (slmgrOutput.Contains("successfully.")) // end of the line; terminate gracefully
            {
                Console.Write($"  {SECTION_BREAK}\n\tActivation completed successfully.\n", Console.ForegroundColor = ckau.DefaultFGColor); // prompt for user input
                return;
            }
            else
            {
                Console.Write("[FAIL!]\n", Console.ForegroundColor = ConsoleColor.Red);
                Console.ResetColor();
                throw new ApplicationException("slmgr.vbs /ato : Unable to activate against any KMS host server in the available pool.");
            }
        }
        throw new ApplicationException("slmgr.vbs /ato : An unknown error occurred."); // strange things are afoot at the Circle K if we end up here
    }
}

public class ProgressBar : IDisposable, IProgress<double>
{
    private const int blockCount = 10; // 
    private readonly TimeSpan animationInterval = TimeSpan.FromSeconds(1.0 / 8); // 
    private const string animation = @"|/-\"; // 
    private readonly Timer timer; // 
    private double currentProgress = 0; // 
    private string currentText = string.Empty; // 
    private bool disposed = false; // 
    private int animationIndex = 0; // 

    public ProgressBar()
    {
        timer = new Timer(TimerHandler); // 
        // A progress bar is only for temporary display in a console window.
        // If the console output is redirected to a file, draw nothing.
        // Otherwise, we'll end up with a lot of garbage in the target file.
        if (!Console.IsOutputRedirected)
        {
            ResetTimer();
        }
    }

    public void Report(double value)
    {
        value = Math.Max(0, Math.Min(1, value)); // Make sure value is in [0..1] range
        Interlocked.Exchange(ref currentProgress, value); // 
    }

    private void TimerHandler(object state)
    {
        lock (timer)
        {
            if (disposed) return; // 
            int progressBlockCount = (int)(currentProgress * blockCount); // 
            int percent = (int)(currentProgress * 100); // 
            string text = string.Format("[{0}{1}] {2,3}% {3}", // 
            new string('≡', progressBlockCount), new string(' ', blockCount - progressBlockCount), percent, animation[animationIndex++ % animation.Length]); // 
            UpdateText(text); // 
            ResetTimer(); // 
        }
    }

    private void UpdateText(string text)
    {
        int commonPrefixLength = 0; // 
        int commonLength = Math.Min(currentText.Length, text.Length); // Get length of common portion
        while (commonPrefixLength < commonLength && text[commonPrefixLength] == currentText[commonPrefixLength])
        {
            commonPrefixLength++;
        }
        StringBuilder outputBuilder = new StringBuilder(); // Backtrack to the first differing character
        outputBuilder.Append('\b', currentText.Length - commonPrefixLength); // move the cursor back the indicated number of spaces
        outputBuilder.Append(text[commonPrefixLength..]); // Output new suffix
        int overlapCount = currentText.Length - text.Length; // If the new text is shorter than the old one: delete overlapping characters
        if (overlapCount > 0) // 
        {
            outputBuilder.Append(' ', overlapCount); // 
            outputBuilder.Append('\b', overlapCount); // 
        }
        Console.Write(outputBuilder); // 
        currentText = text; // 
    }

    private void ResetTimer()
    {
        timer.Change(animationInterval, TimeSpan.FromMilliseconds(-1)); // update the animation interval
    }

    public void Dispose()
    {
        lock (timer)
        {
            disposed = true; // 
            UpdateText(string.Empty); // 
        }
    }
}
