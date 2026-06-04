const fs = require("fs");
const path = require("path");

const telemetryPath = path.join(__dirname, "../src/data/telemetry.json");
const outputPath = path.join(__dirname, "../src/data/coverage.json");

const telemetry = JSON.parse(
  fs.readFileSync(telemetryPath, "utf-8")
);

const techniques = [
  {
    technique_id: "T1059",
    technique_name: "Command and Scripting Interpreter",
    required_telemetry: [
      "powershell_script_block_logging",
      "edr_process_events",
      "windows_security_events",
    ],
  },
  {
    technique_id: "T1071",
    technique_name: "Application Layer Protocol",
    required_telemetry: [
      "dns_logs",
      "edr_process_events",
    ],
  },
  {
    technique_id: "T1003",
    technique_name: "OS Credential Dumping",
    required_telemetry: [
      "edr_process_events",
      "windows_security_events",
    ],
  },
];

function scoreTechnique(requiredTelemetry) {
  const available = requiredTelemetry.filter(
    (item) => telemetry[item]
  );

  const missing = requiredTelemetry.filter(
    (item) => !telemetry[item]
  );

  let score = 1;
  let status = "weak";

  if (available.length === requiredTelemetry.length) {
    score = 3;
    status = "strong";
  } else if (available.length > 0) {
    score = 2;
    status = "partial";
  }

  return {
    score,
    status,
    available,
    missing,
  };
}

const coverage = techniques.map((technique) => {
  const result = scoreTechnique(
    technique.required_telemetry
  );

  return {
    technique_id: technique.technique_id,
    technique_name: technique.technique_name,
    score: result.score,
    status: result.status,
    available_telemetry: result.available,
    missing_telemetry: result.missing,
    reason:
      result.missing.length > 0
        ? `Missing telemetry: ${result.missing.join(", ")}`
        : "All required telemetry available.",
  };
});

fs.writeFileSync(
  outputPath,
  JSON.stringify(coverage, null, 2)
);

console.log(
  `Generated coverage report with ${coverage.length} techniques.`
);