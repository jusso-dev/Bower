// Usage: Bower.EtlStacks TRACE.etl PROCESS SYMBOL_DIR [TOP]
// Prints metadata only: sample counts per module, and inclusive/exclusive samples per frame.
using Microsoft.Diagnostics.Symbols;
using Microsoft.Diagnostics.Tracing.Etlx;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

string etl = args[0], processName = args[1], symbols = args[2];
int top = args.Length > 3 ? int.Parse(args[3]) : 40;
using TraceLog log = TraceLog.OpenOrConvert(etl, new TraceLogOptions { ConversionLog = TextWriter.Null });
using SymbolReader reader = new(TextWriter.Null, symbols) { SecurityCheck = _ => true };
var processes = log.Processes.Where(p => p.Name.Equals(processName, StringComparison.OrdinalIgnoreCase)).ToList();
foreach (TraceProcess process in processes)
{
    foreach (TraceLoadedModule module in process.LoadedModules)
    {
        string name = Path.GetFileName(module.FilePath);
        if (name.StartsWith("Bower", StringComparison.OrdinalIgnoreCase) || name.StartsWith("e_sqlite3", StringComparison.OrdinalIgnoreCase))
        {
            log.CodeAddresses.LookupSymbolsForModule(reader, module.ModuleFile);
        }
    }
}

var pids = processes.Select(p => p.ProcessID).ToHashSet();
Dictionary<string, int> modules = new(), inclusive = new(), exclusive = new();
int samples = 0;
foreach (var data in log.Events.Filter(e => e is SampledProfileTraceData && pids.Contains(e.ProcessID)))
{
    samples++;
    TraceCallStack? stack = data.CallStack();
    HashSet<string> seen = [];
    bool first = true;
    for (; stack is not null; stack = stack.Caller)
    {
        TraceCodeAddress address = stack.CodeAddress;
        string module = address.ModuleName ?? "?";
        string frame = module + "!" + (string.IsNullOrEmpty(address.FullMethodName) ? "?" : address.FullMethodName);
        if (first)
        {
            modules[module] = modules.GetValueOrDefault(module) + 1;
            exclusive[frame] = exclusive.GetValueOrDefault(frame) + 1;
            first = false;
        }

        if (seen.Add(frame))
        {
            inclusive[frame] = inclusive.GetValueOrDefault(frame) + 1;
        }
    }
}

Console.WriteLine($"process={processName} pids={string.Join(',', pids)} samples={samples}");
Console.WriteLine("== exclusive by module");
foreach (var item in modules.OrderByDescending(x => x.Value).Take(15)) Console.WriteLine($"{item.Value,7} {100.0 * item.Value / Math.Max(1, samples),5:F1}% {item.Key}");
Console.WriteLine("== exclusive by frame");
foreach (var item in exclusive.OrderByDescending(x => x.Value).Take(top)) Console.WriteLine($"{item.Value,7} {100.0 * item.Value / Math.Max(1, samples),5:F1}% {item.Key}");
Console.WriteLine("== inclusive by frame (Bower code)");
foreach (var item in inclusive.Where(x => x.Key.Contains("Bower", StringComparison.Ordinal) && !x.Key.EndsWith("!?", StringComparison.Ordinal))
    .OrderByDescending(x => x.Value).Take(top)) Console.WriteLine($"{item.Value,7} {100.0 * item.Value / Math.Max(1, samples),5:F1}% {item.Key}");
