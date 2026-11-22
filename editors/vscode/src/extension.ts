import * as vscode from "vscode";
import * as path from "path";
import * as cp from "child_process";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;
let diagnosticCollection: vscode.DiagnosticCollection | undefined;

export function activate(context: vscode.ExtensionContext): void {
  const config = vscode.workspace.getConfiguration("sorobanGuard");
  const binaryPath: string = config.get("path") ?? "soroban-guard";
  const useLsp: boolean = config.get("useLsp") ?? true;

  if (useLsp) {
    startLspClient(context, binaryPath);
  } else {
    startJsonFallback(context, binaryPath);
  }
}

function startLspClient(
  context: vscode.ExtensionContext,
  binaryPath: string
): void {
  const serverOptions: ServerOptions = {
    command: binaryPath,
    args: ["lsp"],
    transport: TransportKind.stdio,
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file", language: "rust" }],
    synchronize: {
      fileEvents: vscode.workspace.createFileSystemWatcher("**/*.rs"),
    },
  };

  client = new LanguageClient(
    "soroban-guard",
    "Soroban Guard",
    serverOptions,
    clientOptions
  );

  client.start();
  context.subscriptions.push({ dispose: () => client?.stop() });
}

function startJsonFallback(
  context: vscode.ExtensionContext,
  binaryPath: string
): void {
  diagnosticCollection =
    vscode.languages.createDiagnosticCollection("soroban-guard");
  context.subscriptions.push(diagnosticCollection);

  const scanOnSave = vscode.workspace.onDidSaveTextDocument((doc) => {
    if (doc.languageId === "rust") {
      runJsonScan(binaryPath, doc.uri.fsPath);
    }
  });
  context.subscriptions.push(scanOnSave);
}

interface SorobanFinding {
  check_name: string;
  severity: "High" | "Medium" | "Low";
  file_path: string;
  line: number;
  description: string;
  rule_url?: string;
}

interface SorobanJsonOutput {
  findings: SorobanFinding[];
}

function runJsonScan(binaryPath: string, filePath: string): void {
  const workspaceFolder = vscode.workspace.getWorkspaceFolder(
    vscode.Uri.file(filePath)
  );
  const cwd = workspaceFolder?.uri.fsPath ?? path.dirname(filePath);

  cp.execFile(
    binaryPath,
    ["scan", "--json", filePath],
    { cwd },
    (err, stdout) => {
      if (!diagnosticCollection) return;
      diagnosticCollection.clear();
      try {
        const output: SorobanJsonOutput = JSON.parse(stdout);
        const diagsByFile = new Map<string, vscode.Diagnostic[]>();
        for (const f of output.findings) {
          const diag = new vscode.Diagnostic(
            new vscode.Range(
              Math.max(0, f.line - 1),
              0,
              Math.max(0, f.line - 1),
              Number.MAX_SAFE_INTEGER
            ),
            f.description,
            severityToVscode(f.severity)
          );
          diag.code = f.rule_url
            ? { value: f.check_name, target: vscode.Uri.parse(f.rule_url) }
            : f.check_name;
          diag.source = "soroban-guard";
          const key = f.file_path;
          if (!diagsByFile.has(key)) diagsByFile.set(key, []);
          diagsByFile.get(key)!.push(diag);
        }
        for (const [fp, diags] of diagsByFile) {
          diagnosticCollection.set(vscode.Uri.file(fp), diags);
        }
      } catch {
        // Parse error or binary not found — silently skip to avoid spamming the user.
      }
    }
  );
}

function severityToVscode(
  sev: "High" | "Medium" | "Low"
): vscode.DiagnosticSeverity {
  switch (sev) {
    case "High":
      return vscode.DiagnosticSeverity.Error;
    case "Medium":
      return vscode.DiagnosticSeverity.Warning;
    case "Low":
      return vscode.DiagnosticSeverity.Information;
  }
}

export function deactivate(): Thenable<void> | undefined {
  if (client) {
    return client.stop();
  }
  diagnosticCollection?.dispose();
  return undefined;
}
