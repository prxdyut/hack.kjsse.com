// Mock Data Generator for Security Analysis
// This file provides utility functions to generate mock security analysis data
// for testing and development purposes.

// Interfaces copied from Chat.tsx
interface FileInfo {
  md5: string;
  sha1: string;
  sha256: string;
  fileSize: number;
  fileType: string;
  magic: string;
  compilationTimestamp?: Date;
}

interface Signature {
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: 'malware' | 'pup' | 'adware' | 'suspicious' | 'clean';
}

interface ScanResult {
  detected: boolean;
  version: string;
  result: string | null;
  update: string;
}

interface VirusTotalResult {
  permalink: string;
  scanDate: Date;
  positives: number;
  total: number;
  scans: { [engine: string]: ScanResult };
}

interface StaticAnalysis {
  scanId: string;
  scanDate: Date;
  detectionRate: number;
  totalScans: number;
  positiveScans: number;
  fileInfo: FileInfo;
  signatures: Signature[];
  virusTotal: VirusTotalResult;
}

interface Process {
  pid: number;
  name: string;
  path: string;
  commandLine: string;
  parentPid: number;
  creationTime: Date;
  isMalicious: boolean;
  signature?: string;
}

interface NetworkActivity {
  processName: string;
  pid: number;
  protocol: 'TCP' | 'UDP' | 'HTTP' | 'DNS' | 'HTTPS';
  localIp: string;
  localPort: number;
  remoteIp: string;
  remotePort: number;
  remoteHostname?: string;
  requestSize?: number;
  responseSize?: number;
  timestamp: Date;
  isMalicious: boolean;
  maliciousReason?: string;
}

interface FileSystemActivity {
  processName: string;
  pid: number;
  operation: 'create' | 'modify' | 'delete' | 'rename' | 'read';
  path: string;
  timestamp: Date;
  isMalicious: boolean;
  maliciousReason?: string;
}

interface RegistryActivity {
  processName: string;
  pid: number;
  operation: 'create' | 'modify' | 'delete' | 'query';
  key: string;
  value?: string;
  data?: string;
  timestamp: Date;
  isMalicious: boolean;
  maliciousReason?: string;
}

interface MitreTactic {
  id: string;
  name: string;
  description: string;
}

interface DynamicAnalysisSummary {
  riskScore: number;
  verdict: 'clean' | 'suspicious' | 'malicious';
  foundMalware: boolean;
  malwareFamily?: string;
  behaviorCategories: string[];
  mitreTactics: MitreTactic[];
}

interface DynamicAnalysis {
  executionId: string;
  executionDate: Date;
  duration: number;
  summary: DynamicAnalysisSummary;
  processes: Process[];
  networkActivity: NetworkActivity[];
  fileSystemActivity: FileSystemActivity[];
  registryActivity: RegistryActivity[];
}

interface AnalysisReport {
  reportId: string;
  fileId: string;
  fileName: string;
  overallVerdict: 'clean' | 'suspicious' | 'malicious';
  threatScore: number;
  staticAnalysis: StaticAnalysis;
  dynamicAnalysis?: DynamicAnalysis;
  analyzedAt: Date;
}

// Helper functions
const generateRandomHash = (length: number): string => {
  return Array(length).fill(0).map(() => Math.floor(Math.random() * 16).toString(16)).join('');
};

const getRandomDateInPast = (daysMax: number = 30): Date => {
  const now = new Date();
  const pastTime = now.getTime() - Math.floor(Math.random() * daysMax * 24 * 60 * 60 * 1000);
  return new Date(pastTime);
};

const getRandomIp = (): string => {
  return `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
};

const getRandomPort = (isWellKnown: boolean = false): number => {
  return isWellKnown 
    ? [80, 443, 22, 21, 25, 53][Math.floor(Math.random() * 6)]
    : Math.floor(Math.random() * 16000) + 49152; // Ephemeral ports
};

// Common malware signatures
const malwareSignatures: Signature[] = [
  {
    name: 'SuspiciousImports',
    description: 'File contains imports commonly used by malware',
    severity: 'medium',
    category: 'suspicious'
  },
  {
    name: 'PossiblePacker',
    description: 'File may be packed with an unknown packer',
    severity: 'medium',
    category: 'suspicious'
  },
  {
    name: 'KnownTrojan',
    description: 'File matches signature of known trojan',
    severity: 'high',
    category: 'malware'
  },
  {
    name: 'SuspiciousEntryPoint',
    description: 'Executable has an unusual entry point',
    severity: 'medium',
    category: 'suspicious'
  },
  {
    name: 'DataObfuscation',
    description: 'File contains obfuscated data or strings',
    severity: 'medium',
    category: 'suspicious'
  },
  {
    name: 'EncryptedCode',
    description: 'File contains encrypted code sections',
    severity: 'high',
    category: 'suspicious'
  },
  {
    name: 'AntiAnalysisTechnique',
    description: 'File employs techniques to prevent analysis',
    severity: 'high',
    category: 'suspicious'
  },
  {
    name: 'RansomwareIndicator',
    description: 'File contains behavior consistent with ransomware',
    severity: 'critical',
    category: 'malware'
  }
];

// Common antivirus engines
const antivirusEngines = [
  'Windows Defender',
  'Kaspersky',
  'McAfee',
  'ClamAV',
  'Symantec',
  'ESET',
  'Avast',
  'AVG',
  'Malwarebytes',
  'Bitdefender',
  'F-Secure',
  'Sophos',
  'Trend Micro',
  'Panda',
  'Webroot'
];

// Malware families
const malwareFamilies = [
  'Emotet',
  'Trickbot',
  'Ryuk',
  'Dridex',
  'Qakbot',
  'AgentTesla',
  'Formbook',
  'Ursnif',
  'LokiBot',
  'Remcos',
  'NanoCore',
  'Azorult',
  'Raccoon',
  'Redline',
  'Zloader'
];

// MITRE ATT&CK tactics
const mitreTactics: MitreTactic[] = [
  {
    id: 'TA0001',
    name: 'Initial Access',
    description: 'Techniques used to gain initial access to a network'
  },
  {
    id: 'TA0002',
    name: 'Execution',
    description: 'Techniques that result in execution of adversary-controlled code'
  },
  {
    id: 'TA0003',
    name: 'Persistence',
    description: 'Techniques used to maintain access to systems across restarts'
  },
  {
    id: 'TA0004',
    name: 'Privilege Escalation',
    description: 'Techniques used to gain higher-level permissions'
  },
  {
    id: 'TA0005',
    name: 'Defense Evasion',
    description: 'Techniques used to avoid detection'
  },
  {
    id: 'TA0006',
    name: 'Credential Access',
    description: 'Techniques for stealing credentials'
  },
  {
    id: 'TA0007',
    name: 'Discovery',
    description: 'Techniques used to gain knowledge about the system and network'
  },
  {
    id: 'TA0008',
    name: 'Lateral Movement',
    description: 'Techniques used to move through the environment'
  },
  {
    id: 'TA0009',
    name: 'Collection',
    description: 'Techniques used to gather data of interest'
  },
  {
    id: 'TA0011',
    name: 'Command and Control',
    description: 'Techniques used to communicate with systems under their control'
  },
  {
    id: 'TA0010',
    name: 'Exfiltration',
    description: 'Techniques used to steal data'
  },
  {
    id: 'TA0040',
    name: 'Impact',
    description: 'Techniques used to disrupt availability or compromise integrity'
  }
];

// Behavior categories
const behaviorCategories = [
  'Process Injection',
  'Registry Modification',
  'Persistence',
  'Data Exfiltration',
  'Encryption',
  'Network Communication',
  'Anti-Analysis',
  'Code Execution',
  'Privilege Escalation',
  'Credential Theft',
  'File Operations',
  'Information Gathering'
];

/**
 * Generates mock static analysis data for a file
 */
export const generateMockStaticAnalysis = (
  fileName: string, 
  maliciousProbability: number = 0.2
): StaticAnalysis => {
  const fileType = fileName.split('.').pop()?.toUpperCase() || 'UNKNOWN';
  const isDetected = Math.random() < maliciousProbability;
  const positiveScans = isDetected ? Math.floor(Math.random() * 5) + 1 : 0; // 1-5 if detected
  const totalScans = 68;
  
  // Generate virus total scans
  const scans: { [engine: string]: ScanResult } = {};
  const selectedEngines = antivirusEngines.sort(() => 0.5 - Math.random()).slice(0, totalScans);
  
  selectedEngines.forEach(engine => {
    const detected = positiveScans > 0 && Math.random() < (positiveScans / totalScans) * 2; // Higher chance for positive engines
    scans[engine] = {
      detected,
      version: `${Math.floor(Math.random() * 20)}.${Math.floor(Math.random() * 20)}.${Math.floor(Math.random() * 1000)}`,
      result: detected ? `${['Trojan', 'Worm', 'Backdoor', 'Spyware', 'Ransomware'][Math.floor(Math.random() * 5)]}:${['Win32', 'Win64', 'Generic'][Math.floor(Math.random() * 3)]}/${['Suspicious', 'Malicious', 'Harmful'][Math.floor(Math.random() * 3)]}.${generateRandomHash(4)}` : null,
      update: `2023${String(Math.floor(Math.random() * 12) + 1).padStart(2, '0')}${String(Math.floor(Math.random() * 28) + 1).padStart(2, '0')}`
    };
  });
  
  // Generate signatures if detected
  const signatureCount = positiveScans;
  const signatures: Signature[] = [];
  
  if (signatureCount > 0) {
    // Shuffle and select a subset of malware signatures
    const shuffledSignatures = [...malwareSignatures].sort(() => 0.5 - Math.random());
    for (let i = 0; i < Math.min(signatureCount, shuffledSignatures.length); i++) {
      signatures.push(shuffledSignatures[i]);
    }
  }
  
  return {
    scanId: `scan-${Date.now()}-${generateRandomHash(8)}`,
    scanDate: new Date(),
    detectionRate: positiveScans / totalScans,
    totalScans,
    positiveScans,
    fileInfo: {
      md5: generateRandomHash(32),
      sha1: generateRandomHash(40),
      sha256: generateRandomHash(64),
      fileSize: Math.floor(Math.random() * 10000000) + 1000, // 1KB to 10MB
      fileType,
      magic: ['PE32 executable for MS Windows', 'MS-DOS executable', 'ELF 64-bit LSB executable', 'PDF document', 'ASCII text', 'Zip archive data'][Math.floor(Math.random() * 6)],
      compilationTimestamp: getRandomDateInPast(365)
    },
    signatures,
    virusTotal: {
      permalink: `https://www.virustotal.com/gui/file/${generateRandomHash(64)}/detection`,
      scanDate: new Date(),
      positives: positiveScans,
      total: totalScans,
      scans
    }
  };
};

/**
 * Generates mock dynamic analysis data for a file
 */
export const generateMockDynamicAnalysis = (
  fileName: string, 
  maliciousProbability: number = 0.2
): DynamicAnalysis => {
  const hasMalware = Math.random() < maliciousProbability;
  const riskScore = hasMalware 
    ? 70 + Math.floor(Math.random() * 30) // 70-99 for malicious
    : Math.random() > 0.7 
      ? 30 + Math.floor(Math.random() * 30) // 30-59 for suspicious
      : Math.floor(Math.random() * 30); // 0-29 for clean
  
  const verdict: 'clean' | 'suspicious' | 'malicious' = 
    riskScore >= 70 ? 'malicious' : 
    riskScore >= 30 ? 'suspicious' : 
    'clean';
  
  // Select behavior categories
  const selectedBehaviorCategories = [];
  if (verdict === 'malicious') {
    // For malicious files, select more suspicious behaviors
    selectedBehaviorCategories.push(...behaviorCategories.slice(0, 6).sort(() => 0.5 - Math.random()).slice(0, 3 + Math.floor(Math.random() * 3)));
  } else if (verdict === 'suspicious') {
    // For suspicious files, mix of normal and suspicious
    selectedBehaviorCategories.push(...behaviorCategories.sort(() => 0.5 - Math.random()).slice(0, 2 + Math.floor(Math.random() * 3)));
  } else {
    // For clean files, just normal behaviors
    selectedBehaviorCategories.push(...behaviorCategories.slice(6).sort(() => 0.5 - Math.random()).slice(0, 1 + Math.floor(Math.random() * 2)));
  }
  
  // Select MITRE tactics
  const selectedMitreTactics: MitreTactic[] = [];
  if (verdict === 'malicious') {
    selectedMitreTactics.push(...mitreTactics.sort(() => 0.5 - Math.random()).slice(0, 2 + Math.floor(Math.random() * 3)));
  } else if (verdict === 'suspicious') {
    selectedMitreTactics.push(...mitreTactics.sort(() => 0.5 - Math.random()).slice(0, 1 + Math.floor(Math.random() * 2)));
  }
  
  // Generate processes
  const processes: Process[] = [
    {
      pid: 1234,
      name: fileName,
      path: `C:\\Users\\Admin\\AppData\\Local\\Temp\\${fileName}`,
      commandLine: `"C:\\Users\\Admin\\AppData\\Local\\Temp\\${fileName}"`,
      parentPid: 4567,
      creationTime: new Date(),
      isMalicious: hasMalware
    }
  ];
  
  // Add more processes if malicious or suspicious
  if (verdict === 'malicious' || verdict === 'suspicious') {
    processes.push({
      pid: 5678,
      name: 'cmd.exe',
      path: 'C:\\Windows\\System32\\cmd.exe',
      commandLine: `cmd.exe /c "copy ${fileName} C:\\ProgramData\\StartMenu\\"`,
      parentPid: 1234,
      creationTime: new Date(Date.now() + 2000),
      isMalicious: verdict === 'malicious'
    });
    
    if (verdict === 'malicious') {
      processes.push({
        pid: 5679,
        name: 'powershell.exe',
        path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: `powershell.exe -WindowStyle Hidden -EncodedCommand ${generateRandomHash(64)}`,
        parentPid: 1234,
        creationTime: new Date(Date.now() + 3000),
        isMalicious: true,
        signature: 'ObfuscatedPowerShell'
      });
    }
  }
  
  // Generate network activity
  const networkActivity: NetworkActivity[] = [];
  
  if (verdict === 'malicious') {
    networkActivity.push({
      processName: fileName,
      pid: 1234,
      protocol: 'HTTP',
      localIp: '192.168.1.5',
      localPort: getRandomPort(),
      remoteIp: getRandomIp(),
      remotePort: 80,
      remoteHostname: `evil-c2-server-${Math.floor(Math.random() * 100)}.com`,
      requestSize: 1024,
      responseSize: 4096,
      timestamp: new Date(Date.now() + 5000),
      isMalicious: true,
      maliciousReason: 'Connection to known malicious host'
    });
    
    networkActivity.push({
      processName: 'powershell.exe',
      pid: 5679,
      protocol: 'HTTPS',
      localIp: '192.168.1.5',
      localPort: getRandomPort(),
      remoteIp: getRandomIp(),
      remotePort: 443,
      timestamp: new Date(Date.now() + 6000),
      isMalicious: true,
      maliciousReason: 'Data exfiltration to suspicious domain'
    });
  }
  
  // Add some benign network activity
  networkActivity.push({
    processName: fileName,
    pid: 1234,
    protocol: 'DNS',
    localIp: '192.168.1.5',
    localPort: getRandomPort(),
    remoteIp: '8.8.8.8',
    remotePort: 53,
    timestamp: new Date(Date.now() + 4000),
    isMalicious: false
  });
  
  networkActivity.push({
    processName: fileName,
    pid: 1234,
    protocol: 'HTTPS',
    localIp: '192.168.1.5',
    localPort: getRandomPort(),
    remoteIp: '172.217.21.228',
    remotePort: 443,
    remoteHostname: 'google.com',
    timestamp: new Date(Date.now() + 4500),
    isMalicious: false
  });
  
  // Generate file system activity
  const fileSystemActivity: FileSystemActivity[] = [
    {
      processName: fileName,
      pid: 1234,
      operation: 'create',
      path: `C:\\Users\\Admin\\AppData\\Local\\Temp\\${generateRandomHash(8)}.tmp`,
      timestamp: new Date(Date.now() + 3000),
      isMalicious: verdict === 'malicious',
      maliciousReason: verdict === 'malicious' ? 'Creates suspicious temporary file' : undefined
    }
  ];
  
  if (verdict === 'malicious' || verdict === 'suspicious') {
    fileSystemActivity.push({
      processName: 'cmd.exe',
      pid: 5678,
      operation: 'create',
      path: verdict === 'malicious' ? `C:\\ProgramData\\StartMenu\\${fileName}` : `C:\\Users\\Admin\\Documents\\${fileName}`,
      timestamp: new Date(Date.now() + 6000),
      isMalicious: verdict === 'malicious',
      maliciousReason: verdict === 'malicious' ? 'Creates file in system directory for persistence' : undefined
    });
  }
  
  if (verdict === 'malicious') {
    fileSystemActivity.push({
      processName: 'powershell.exe',
      pid: 5679,
      operation: 'modify',
      path: 'C:\\Windows\\System32\\drivers\\etc\\hosts',
      timestamp: new Date(Date.now() + 7000),
      isMalicious: true,
      maliciousReason: 'Modifies system hosts file'
    });
  }
  
  // Generate registry activity
  const registryActivity: RegistryActivity[] = [];
  
  if (verdict === 'malicious') {
    registryActivity.push({
      processName: fileName,
      pid: 1234,
      operation: 'create',
      key: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
      value: 'MaliciousStartup',
      data: `C:\\ProgramData\\StartMenu\\${fileName}`,
      timestamp: new Date(Date.now() + 7000),
      isMalicious: true,
      maliciousReason: 'Creates autorun registry key for persistence'
    });
    
    registryActivity.push({
      processName: 'powershell.exe',
      pid: 5679,
      operation: 'modify',
      key: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile',
      value: 'EnableFirewall',
      data: '0',
      timestamp: new Date(Date.now() + 8000),
      isMalicious: true,
      maliciousReason: 'Disables Windows Firewall'
    });
  } else if (verdict === 'suspicious') {
    registryActivity.push({
      processName: fileName,
      pid: 1234,
      operation: 'query',
      key: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
      timestamp: new Date(Date.now() + 6000),
      isMalicious: false
    });
  }
  
  return {
    executionId: `exec-${Date.now()}-${generateRandomHash(8)}`,
    executionDate: new Date(),
    duration: 30 + Math.floor(Math.random() * 60), // 30-90 seconds
    summary: {
      riskScore,
      verdict,
      foundMalware: hasMalware,
      malwareFamily: hasMalware ? malwareFamilies[Math.floor(Math.random() * malwareFamilies.length)] : undefined,
      behaviorCategories: selectedBehaviorCategories,
      mitreTactics: selectedMitreTactics
    },
    processes,
    networkActivity,
    fileSystemActivity,
    registryActivity
  };
};

/**
 * Generates a complete mock analysis report for a file
 */
export const generateMockAnalysisReport = (
  fileId: string, 
  fileName: string, 
  analysisType: 'static' | 'deep' = 'static',
  maliciousProbability: number = 0.2
): AnalysisReport => {
  // Generate static analysis
  const staticAnalysis = generateMockStaticAnalysis(fileName, maliciousProbability);
  
  // Generate dynamic analysis if deep scan
  let dynamicAnalysis: DynamicAnalysis | undefined = undefined;
  if (analysisType === 'deep') {
    dynamicAnalysis = generateMockDynamicAnalysis(fileName, maliciousProbability);
  }
  
  // Determine overall verdict and threat score
  const staticVerdict = staticAnalysis.positiveScans > 0 ? 'suspicious' : 'clean';
  const dynamicVerdict = dynamicAnalysis?.summary.verdict ?? 'clean';
  
  const overallVerdict: 'clean' | 'suspicious' | 'malicious' = 
    dynamicVerdict === 'malicious' || staticVerdict === 'malicious' ? 'malicious' :
    dynamicVerdict === 'suspicious' || staticVerdict === 'suspicious' ? 'suspicious' :
    'clean';
  
  // Calculate threat score
  let threatScore = 0;
  if (overallVerdict === 'malicious') {
    threatScore = 70 + Math.floor(Math.random() * 30);
  } else if (overallVerdict === 'suspicious') {
    threatScore = 30 + Math.floor(Math.random() * 40);
  } else {
    threatScore = Math.floor(Math.random() * 30);
  }
  
  return {
    reportId: `report-${Date.now()}-${generateRandomHash(8)}`,
    fileId,
    fileName,
    overallVerdict,
    threatScore,
    staticAnalysis,
    dynamicAnalysis,
    analyzedAt: new Date()
  };
};

/**
 * Updates an existing report with dynamic analysis
 */
export const addDynamicAnalysisToReport = (
  report: AnalysisReport,
  maliciousProbability: number = 0.2
): AnalysisReport => {
  // Generate dynamic analysis
  const dynamicAnalysis = generateMockDynamicAnalysis(report.fileName, maliciousProbability);
  
  // Update verdict based on dynamic analysis
  const newVerdict: 'clean' | 'suspicious' | 'malicious' = 
    dynamicAnalysis.summary.verdict === 'malicious' ? 'malicious' :
    dynamicAnalysis.summary.verdict === 'suspicious' || report.overallVerdict === 'suspicious' ? 'suspicious' :
    'clean';
  
  // Update threat score
  let newThreatScore = report.threatScore;
  if (newVerdict === 'malicious' && report.overallVerdict !== 'malicious') {
    newThreatScore = 70 + Math.floor(Math.random() * 30);
  } else if (newVerdict === 'suspicious' && report.overallVerdict === 'clean') {
    newThreatScore = 30 + Math.floor(Math.random() * 40);
  }
  
  return {
    ...report,
    overallVerdict: newVerdict,
    threatScore: newThreatScore,
    dynamicAnalysis,
    analyzedAt: new Date() // Update analysis timestamp
  };
};

// Export a function to generate several mock file reports
export const generateMockFileReports = (
  count: number = 5, 
  maliciousProbability: number = 0.2
): AnalysisReport[] => {
  const fileTypes = ['exe', 'dll', 'pdf', 'doc', 'xls', 'zip', 'js', 'bat', 'ps1', 'apk'];
  const reports: AnalysisReport[] = [];
  
  for (let i = 0; i < count; i++) {
    const fileId = `file-${Date.now()}-${generateRandomHash(8)}`;
    const fileType = fileTypes[Math.floor(Math.random() * fileTypes.length)];
    const fileName = `sample-${i + 1}.${fileType}`;
    const analysisType = Math.random() > 0.5 ? 'deep' : 'static';
    
    reports.push(generateMockAnalysisReport(
      fileId,
      fileName,
      analysisType,
      maliciousProbability
    ));
  }
  
  return reports;
}; 