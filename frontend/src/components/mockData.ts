// Mock data generation functions for the security analysis application
import { AnalysisReport, DynamicAnalysis, StaticAnalysis } from './types';

/**
 * Generates a mock analysis report for a file
 */
export const generateMockAnalysisReport = (fileId: string, fileName: string, scanLevel: string): AnalysisReport => {
  // Generate mock static analysis data
  const staticAnalysis: StaticAnalysis = {
    scanId: `scan-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    scanDate: new Date(),
    detectionRate: Math.random() > 0.7 ? Math.random() * 0.1 : 0, // 30% chance of detection
    totalScans: 68,
    positiveScans: Math.floor(Math.random() * 3), // 0-2 positive scans
    fileInfo: {
      md5: Array(32).fill(0).map(() => Math.floor(Math.random() * 16).toString(16)).join(''),
      sha1: Array(40).fill(0).map(() => Math.floor(Math.random() * 16).toString(16)).join(''),
      sha256: Array(64).fill(0).map(() => Math.floor(Math.random() * 16).toString(16)).join(''),
      fileSize: Math.floor(Math.random() * 10000000) + 1000, // 1KB to 10MB
      fileType: fileName.split('.').pop()?.toUpperCase() || 'UNKNOWN',
      magic: 'PE32 executable for MS Windows',
      compilationTimestamp: new Date(Date.now() - Math.floor(Math.random() * 10000000000))
    },
    signatures: [],
    virusTotal: {
      permalink: `https://www.virustotal.com/gui/file/${Array(64).fill(0).map(() => Math.floor(Math.random() * 16).toString(16)).join('')}/detection`,
      scanDate: new Date(),
      positives: Math.floor(Math.random() * 3), // 0-2 positive detections
      total: 68,
      scans: {
        'Windows Defender': {
          detected: Math.random() > 0.9,
          version: '1.1.19800.4',
          result: Math.random() > 0.9 ? 'Trojan:Win32/Occamy.C' : null,
          update: '20230601'
        },
        'Kaspersky': {
          detected: Math.random() > 0.9,
          version: '21.0.1.45',
          result: Math.random() > 0.9 ? 'HEUR:Trojan.Win32.Generic' : null,
          update: '20230601'
        },
        'McAfee': {
          detected: Math.random() > 0.9,
          version: '6.0.6.653',
          result: Math.random() > 0.9 ? 'W32/Obfuscated.Y' : null,
          update: '20230601'
        },
        'ClamAV': {
          detected: Math.random() > 0.9,
          version: '0.104.0.0',
          result: Math.random() > 0.9 ? 'Win.Trojan.Generic-9829433-0' : null,
          update: '20230601'
        },
        'Symantec': {
          detected: Math.random() > 0.9,
          version: '1.17.0.0',
          result: Math.random() > 0.9 ? 'Trojan.Gen.2' : null,
          update: '20230601'
        }
      }
    }
  }

  // Add some signatures if we have "detections"
  if (staticAnalysis.positiveScans > 0) {
    staticAnalysis.signatures.push({
      name: 'SuspiciousImports',
      description: 'File contains imports commonly used by malware',
      severity: 'medium',
      category: 'suspicious'
    });
    
    if (staticAnalysis.positiveScans > 1) {
      staticAnalysis.signatures.push({
        name: 'PossiblePacker',
        description: 'File may be packed with an unknown packer',
        severity: 'medium',
        category: 'suspicious'
      });
    }
  }

  // Generate dynamic analysis data only for deep scans
  let dynamicAnalysis: DynamicAnalysis | undefined = undefined;
  
  if (scanLevel === 'deep') {
    dynamicAnalysis = generateMockDynamicAnalysis(fileName);
  }
  
  // Combined report
  const hasDynamicMalware = dynamicAnalysis?.summary.verdict === 'malicious';
  const hasStaticDetections = staticAnalysis.positiveScans > 0;
  
  return {
    reportId: `report-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    fileId: fileId,
    fileName: fileName,
    overallVerdict: hasDynamicMalware ? 'malicious' : (hasStaticDetections ? 'suspicious' : 'clean'),
    threatScore: hasDynamicMalware 
      ? 70 + Math.floor(Math.random() * 30) 
      : (hasStaticDetections ? 30 + Math.floor(Math.random() * 30) : Math.floor(Math.random() * 20)),
    staticAnalysis,
    dynamicAnalysis,
    analyzedAt: new Date()
  }
}

/**
 * Generates mock dynamic analysis data for a file
 */
export const generateMockDynamicAnalysis = (fileName: string): DynamicAnalysis => {
  const hasMalware = Math.random() > 0.8; // 20% chance of malware in dynamic analysis
  
  return {
    executionId: `exec-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    executionDate: new Date(),
    duration: Math.floor(Math.random() * 60) + 30, // 30-90 seconds
    summary: {
      riskScore: hasMalware ? 70 + Math.floor(Math.random() * 30) : Math.floor(Math.random() * 20),
      verdict: hasMalware ? 'malicious' : (Math.random() > 0.7 ? 'suspicious' : 'clean'),
      foundMalware: hasMalware,
      malwareFamily: hasMalware ? ['Emotet', 'Trickbot', 'Ryuk', 'Dridex'][Math.floor(Math.random() * 4)] : undefined,
      behaviorCategories: hasMalware 
        ? ['Process Injection', 'Registry Modification', 'Persistence', 'Data Exfiltration']
        : ['File Operations', 'Network Connections'],
      mitreTactics: hasMalware ? [
        {
          id: 'TA0003',
          name: 'Persistence',
          description: 'Maintains access to system through system restart or credential change'
        },
        {
          id: 'TA0005',
          name: 'Defense Evasion',
          description: 'Avoids detection by security products'
        }
      ] : []
    },
    processes: [
      {
        pid: 1234,
        name: fileName,
        path: `C:\\Users\\Admin\\AppData\\Local\\Temp\\${fileName}`,
        commandLine: `"C:\\Users\\Admin\\AppData\\Local\\Temp\\${fileName}"`,
        parentPid: 4567,
        creationTime: new Date(),
        isMalicious: hasMalware
      },
      {
        pid: 5678,
        name: 'cmd.exe',
        path: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: `cmd.exe /c "copy ${fileName} C:\\ProgramData\\StartMenu\\"`,
        parentPid: 1234,
        creationTime: new Date(Date.now() + 2000),
        isMalicious: hasMalware
      }
    ],
    networkActivity: hasMalware ? [
      {
        processName: fileName,
        pid: 1234,
        protocol: 'HTTP',
        localIp: '192.168.1.5',
        localPort: 49233,
        remoteIp: '185.66.87.32',
        remotePort: 80,
        remoteHostname: 'evil-c2-server.com',
        requestSize: 1024,
        responseSize: 4096,
        timestamp: new Date(Date.now() + 5000),
        isMalicious: true,
        maliciousReason: 'Connection to known malicious host'
      },
      {
        processName: fileName,
        pid: 1234,
        protocol: 'DNS',
        localIp: '192.168.1.5',
        localPort: 49234,
        remoteIp: '8.8.8.8',
        remotePort: 53,
        timestamp: new Date(Date.now() + 4000),
        isMalicious: false
      }
    ] : [
      {
        processName: fileName,
        pid: 1234,
        protocol: 'HTTPS',
        localIp: '192.168.1.5',
        localPort: 49234,
        remoteIp: '172.217.21.228',
        remotePort: 443,
        remoteHostname: 'google.com',
        timestamp: new Date(Date.now() + 4000),
        isMalicious: false
      }
    ],
    fileSystemActivity: [
      {
        processName: fileName,
        pid: 1234,
        operation: 'create',
        path: `C:\\Users\\Admin\\AppData\\Local\\Temp\\${Math.random().toString(36).substring(7)}.tmp`,
        timestamp: new Date(Date.now() + 3000),
        isMalicious: hasMalware,
        maliciousReason: hasMalware ? 'Creates suspicious temporary file' : undefined
      },
      {
        processName: 'cmd.exe',
        pid: 5678,
        operation: 'create',
        path: hasMalware ? `C:\\ProgramData\\StartMenu\\${fileName}` : `C:\\Users\\Admin\\Documents\\${fileName}`,
        timestamp: new Date(Date.now() + 6000),
        isMalicious: hasMalware,
        maliciousReason: hasMalware ? 'Creates file in system directory for persistence' : undefined
      }
    ],
    registryActivity: hasMalware ? [
      {
        processName: fileName,
        pid: 1234,
        operation: 'create',
        key: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        value: 'MaliciousStartup',
        data: `C:\\ProgramData\\StartMenu\\${fileName}`,
        timestamp: new Date(Date.now() + 7000),
        isMalicious: true,
        maliciousReason: 'Creates autorun registry key for persistence'
      }
    ] : []
  };
} 