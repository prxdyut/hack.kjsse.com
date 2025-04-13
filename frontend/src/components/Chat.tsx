import { useState, useRef, useEffect, ChangeEvent, FormEvent } from 'react'

// Using CustomFile to avoid conflict with DOM File type
interface CustomFile {
  id: string
  name: string
  size: string
  type: string
  url: string
  status: 'uploading' | 'processing' | 'completed' | 'error'
  progress?: number
  originalFile?: File // Store the original File object
  timestamp?: Date
  analysisReport?: AnalysisReport // New field for the analysis report
}

interface Message {
  id: number
  text: string
  sender: 'user' | 'assistant'
  files?: CustomFile[]
  timestamp: Date
}

// Static Analysis Interfaces
interface StaticAnalysis {
  scanId: string
  scanDate: Date
  detectionRate: number
  totalScans: number
  positiveScans: number
  fileInfo: FileInfo
  signatures: Signature[]
  virusTotal: VirusTotalResult
}

interface FileInfo {
  md5: string
  sha1: string
  sha256: string
  fileSize: number
  fileType: string
  magic: string
  compilationTimestamp?: Date
}

interface Signature {
  name: string
  description: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  category: 'malware' | 'pup' | 'adware' | 'suspicious' | 'clean'
}

interface VirusTotalResult {
  permalink: string
  scanDate: Date
  positives: number
  total: number
  scans: { [engine: string]: ScanResult }
}

interface ScanResult {
  detected: boolean
  version: string
  result: string | null
  update: string
}

// Dynamic Analysis Interfaces
interface DynamicAnalysis {
  executionId: string
  executionDate: Date
  duration: number
  summary: DynamicAnalysisSummary
  processes: Process[]
  networkActivity: NetworkActivity[]
  fileSystemActivity: FileSystemActivity[]
  registryActivity: RegistryActivity[]
}

interface DynamicAnalysisSummary {
  riskScore: number
  verdict: 'clean' | 'suspicious' | 'malicious'
  foundMalware: boolean
  malwareFamily?: string
  behaviorCategories: string[]
  mitreTactics: MitreTactic[]
}

interface MitreTactic {
  id: string
  name: string
  description: string
}

interface Process {
  pid: number
  name: string
  path: string
  commandLine: string
  parentPid: number
  creationTime: Date
  isMalicious: boolean
  signature?: string
}

interface NetworkActivity {
  processName: string
  pid: number
  protocol: 'TCP' | 'UDP' | 'HTTP' | 'DNS' | 'HTTPS'
  localIp: string
  localPort: number
  remoteIp: string
  remotePort: number
  remoteHostname?: string
  requestSize?: number
  responseSize?: number
  timestamp: Date
  isMalicious: boolean
  maliciousReason?: string
}

interface FileSystemActivity {
  processName: string
  pid: number
  operation: 'create' | 'modify' | 'delete' | 'rename' | 'read'
  path: string
  timestamp: Date
  isMalicious: boolean
  maliciousReason?: string
}

interface RegistryActivity {
  processName: string
  pid: number
  operation: 'create' | 'modify' | 'delete' | 'query'
  key: string
  value?: string
  data?: string
  timestamp: Date
  isMalicious: boolean
  maliciousReason?: string
}

// Combined Analysis Report
interface AnalysisReport {
  reportId: string
  fileId: string
  fileName: string
  overallVerdict: 'clean' | 'suspicious' | 'malicious'
  threatScore: number
  staticAnalysis: StaticAnalysis
  dynamicAnalysis?: DynamicAnalysis // Optional since not all files may undergo dynamic analysis
  analyzedAt: Date
}

export default function Chat() {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: 1,
      text: "Drop files to begin security analysis.",
      sender: "assistant",
      timestamp: new Date()
    }
  ])
  const [files, setFiles] = useState<CustomFile[]>([])
  const [inputMessage, setInputMessage] = useState<string>("")
  const [isTyping, setIsTyping] = useState(false)
  const [activeTab, setActiveTab] = useState<'files'>('files')
  const [isSidebarCollapsed, setSidebarCollapsed] = useState(true)
  const [activePage, setActivePage] = useState<'home' | 'scanner' | 'reports' | 'settings'>('scanner')
  const [selectedFile, setSelectedFile] = useState<CustomFile | null>(null)
  const [isFileDetailOpen, setIsFileDetailOpen] = useState(false)
  const [scanLevel, setScanLevel] = useState<'basic' | 'deep'>('basic')
  const [darkMode, setDarkMode] = useState(true)
  const [activeReportTab, setActiveReportTab] = useState<'static' | 'dynamic'>('static')
  
  const fileInputRef = useRef<HTMLInputElement>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const dropAreaRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])
  
  useEffect(() => {
    const dropArea = dropAreaRef.current
    if (!dropArea) return
    
    const preventDefault = (e: Event) => {
      e.preventDefault()
      e.stopPropagation()
    }
    
    const handleDragOver = (e: DragEvent) => {
      preventDefault(e)
      dropArea.classList.add('border-emerald-400')
    }
    
    const handleDragLeave = (e: DragEvent) => {
      preventDefault(e)
      dropArea.classList.remove('border-emerald-400')
    }
    
    const handleDrop = (e: DragEvent) => {
      preventDefault(e)
      dropArea.classList.remove('border-emerald-400')
      
      if (e.dataTransfer?.files) {
        // Fixed type error by converting to correct type
        const fileList = Array.from(e.dataTransfer.files)
        handleFiles(fileList)
      }
    }
    
    dropArea.addEventListener('dragover', handleDragOver)
    dropArea.addEventListener('dragleave', handleDragLeave)
    dropArea.addEventListener('drop', handleDrop)
    
    return () => {
      dropArea.removeEventListener('dragover', handleDragOver)
      dropArea.removeEventListener('dragleave', handleDragLeave)
      dropArea.removeEventListener('drop', handleDrop)
    }
  }, [])

  const handleFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      // Fixed type error by converting to correct type
      const fileList = Array.from(e.target.files)
      handleFiles(fileList)
    }
  }
  
  const handleFiles = (fileList: File[]) => {
    const newFiles = fileList.map(file => ({
      id: `file-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      name: file.name,
      size: formatFileSize(file.size), // Now expecting a number parameter
      type: file.type,
      url: URL.createObjectURL(file), // Now using the original File which is a Blob
      status: 'uploading' as const,
      progress: 0,
      originalFile: file, // Store the original File
      timestamp: new Date()
    }))
    
    setFiles(prev => [...prev, ...newFiles])
    
    // Simulate file upload progress
    newFiles.forEach(file => {
      const interval = setInterval(() => {
        setFiles(prev => 
          prev.map(f => 
            f.id === file.id 
              ? { 
                  ...f, 
                  progress: (f.progress ?? 0) < 100 ? (f.progress ?? 0) + 10 : 100,
                  status: (f.progress ?? 0) >= 90 ? 'processing' : 'uploading'
                }
              : f
          )
        )
      }, 300)
      
      // Simulate file processing completion
      setTimeout(() => {
        clearInterval(interval)
        setFiles(prev => 
          prev.map(f => 
            f.id === file.id ? { ...f, status: 'completed' } : f
          )
        )
        
        const newMessage: Message = {
          id: Date.now(),
          text: `I've uploaded ${fileList.length > 1 ? 'some files' : 'a file'} for security analysis.`,
          sender: 'user',
          files: [file],
          timestamp: new Date()
        }
        
        setMessages(prev => [...prev, newMessage])
        simulateResponse(file.name)
      }, 4000)
    })
  }
  
  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    
    if (!inputMessage.trim()) return

    const newMessage: Message = {
      id: Date.now(),
      text: inputMessage.trim(),
      sender: 'user',
      timestamp: new Date()
    }

    setMessages(prev => [...prev, newMessage])
    setInputMessage('')
    
    simulateResponse()
  }
  
  const simulateResponse = (fileName?: string) => {
    setIsTyping(true)
    
    setTimeout(() => {
      setIsTyping(false)
      
      const responses = [
        fileName 
          ? `I've analyzed "${fileName}". This file has been scanned for security threats. Would you like me to perform a deeper malware scan or analyze its content?`
          : "I can help you scan your files for security threats. What would you like me to analyze?",
        "I can scan files for malware, analyze code for vulnerabilities, or check documents for suspicious content.",
        "Would you like me to perform a threat assessment on this file?",
        "I can run a security check on this file to identify potential risks. Should I proceed?"
      ]
      
      const botResponse: Message = {
        id: Date.now(),
        text: fileName ? responses[0] : responses[Math.floor(Math.random() * responses.length)],
        sender: 'assistant',
        timestamp: new Date()
      }
      
      setMessages(prev => [...prev, botResponse])
    }, 1500)
  }
  
  const removeFile = (fileId: string) => {
    setFiles(prev => prev.filter(f => f.id !== fileId))
  }

  const handleViewFileDetails = (file: CustomFile) => {
    setSelectedFile(file)
    setIsFileDetailOpen(true)
  }

  const handleCloseFileDetails = () => {
    setIsFileDetailOpen(false)
    setSelectedFile(null)
  }

  // File status badge component
  const FileStatusBadge = ({ status }: { status: string }) => {
    switch(status) {
      case 'uploading':
        return (
          <div className="text-xs text-cyan-400 flex items-center" role="status">
            <svg className="w-3 h-3 mr-1 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            Uploading...
          </div>
        )
      case 'processing':
        return (
          <div className="text-xs text-amber-400 flex items-center" role="status">
            <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            Scanning...
          </div>
        )
      case 'completed':
        return (
          <div className="text-xs text-emerald-400 flex items-center" role="status">
            <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            Secured
          </div>
        )
      case 'error':
        return (
          <div className="text-xs text-red-400 flex items-center" role="status">
            <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            Failed
          </div>
        )
      default:
        return null
    }
  }

  const handleScanLevelChange = (level: 'basic' | 'deep') => {
    setScanLevel(level)
  }

  const runFullScan = () => {
    if (files.length === 0) return
    
    // Mark all files as processing
    setFiles(files.map(file => ({
      ...file,
      status: 'processing',
      progress: 0
    })))
    
    // Process all files
    files.forEach(file => {
      const interval = setInterval(() => {
        setFiles(prev => 
          prev.map(f => 
            f.id === file.id 
              ? { 
                  ...f, 
                  progress: (f.progress ?? 0) < 100 ? (f.progress ?? 0) + 5 : 100,
                  status: (f.progress ?? 0) >= 95 ? 'completed' : 'processing'
                }
              : f
          )
        )
      }, 200)
      
      // Complete the scan based on scan level
      const timeToComplete = scanLevel === 'basic' ? 3000 : 5000
      
      setTimeout(() => {
        clearInterval(interval)
        setFiles(prev => 
          prev.map(f => 
            f.id === file.id ? { 
              ...f, 
              status: 'completed', 
              progress: 100,
              analysisReport: generateMockAnalysisReport(f.id, f.name, scanLevel === 'basic' ? 'static' : 'deep')
            } : f
          )
        )
      }, timeToComplete)
    })
  }

  // Run dynamic analysis on a file
  const runDynamicAnalysis = (fileId: string, fileName: string) => {
    // Mark file as processing
    setFiles(prev => 
      prev.map(f => 
        f.id === fileId 
          ? { 
              ...f, 
              status: 'processing',
              progress: 0
            } 
          : f
      )
    )
    
    // If this is the selected file, immediately update the view to show processing state
    if (selectedFile && selectedFile.id === fileId) {
      setSelectedFile(prev => {
        if (!prev) return null;
        return {
          ...prev,
          status: 'processing',
          progress: 0
        };
      });
    }
    
    // Simulate processing
    const interval = setInterval(() => {
      setFiles(prev => {
        const updatedFiles = prev.map(f => 
          f.id === fileId 
            ? { 
                ...f, 
                progress: (f.progress ?? 0) < 100 ? (f.progress ?? 0) + 5 : 100,
                status: (f.progress ?? 0) >= 95 ? 'completed' : 'processing'
              } 
            : f
        );
        
        // Update selectedFile if it's the one being processed
        if (selectedFile && selectedFile.id === fileId) {
          const updatedFile = updatedFiles.find(f => f.id === fileId);
          if (updatedFile) {
            setSelectedFile(updatedFile);
          }
        }
        
        return updatedFiles;
      });
    }, 200)
    
    // Complete the dynamic analysis
    setTimeout(() => {
      clearInterval(interval)
      
      setFiles(prev => {
        const updatedFiles = prev.map(f => {
          if (f.id === fileId) {
            // Get the existing report if it exists
            const existingReport = f.analysisReport;
            
            // Generate a new dynamic analysis
            const dynamicAnalysis = generateMockDynamicAnalysis(fileName);
            
            // Combine with existing report or create new one
            const updatedReport: AnalysisReport = existingReport 
              ? {
                  ...existingReport,
                  dynamicAnalysis,
                  // Update verdict and threat score based on dynamic analysis
                  overallVerdict: dynamicAnalysis.summary.verdict === 'malicious' 
                    ? 'malicious' 
                    : (dynamicAnalysis.summary.verdict === 'suspicious' || existingReport.overallVerdict === 'suspicious') 
                      ? 'suspicious' 
                      : 'clean',
                  threatScore: dynamicAnalysis.summary.verdict === 'malicious'
                    ? 70 + Math.floor(Math.random() * 30)
                    : dynamicAnalysis.summary.verdict === 'suspicious'
                      ? 40 + Math.floor(Math.random() * 30)
                      : Math.min(existingReport.threatScore, 30)
                }
              : generateMockAnalysisReport(f.id, f.name, 'deep');
            
            return { 
              ...f, 
              status: 'completed', 
              progress: 100,
              analysisReport: updatedReport
            };
          }
          return f;
        });
        
        // Update selectedFile with the processed file data
        if (selectedFile && selectedFile.id === fileId) {
          const updatedFile = updatedFiles.find(f => f.id === fileId);
          if (updatedFile) {
            setSelectedFile(updatedFile);
            // Switch to dynamic analysis tab
            setActiveReportTab('dynamic');
          }
        }
        
        return updatedFiles;
      });
      
    }, 6000); // Dynamic analysis takes longer
  }

  // Mock analysis report generation function
  const generateMockAnalysisReport = (fileId: string, fileName: string, scanLevel: string): AnalysisReport => {
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

  // Helper function to generate mock dynamic analysis
  const generateMockDynamicAnalysis = (fileName: string): DynamicAnalysis => {
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

  return (
    <div className={`flex h-screen ${darkMode ? 'bg-gradient-to-tr from-slate-950 via-gray-900 to-slate-900' : 'bg-gradient-to-tr from-gray-100 to-gray-200'}`}>
      {/* Sidebar */}
      <div className={`${isSidebarCollapsed ? 'w-16' : 'w-64'} ${darkMode ? 'bg-black/50 border-emerald-900/30' : 'bg-white/80 border-gray-200'} backdrop-blur-md border-r flex flex-col transition-all duration-300 ease-in-out`}
           role="navigation" 
           aria-label="Main navigation"
      >
        
        {/* Sidebar Header */}
        <div className={`p-4 ${darkMode ? 'border-emerald-900/30' : 'border-gray-200'} border-b flex items-center justify-between`}>
          {!isSidebarCollapsed && (
            <h1 className={`text-lg font-bold ${darkMode ? 'bg-gradient-to-r from-emerald-400 via-teal-400 to-cyan-500 bg-clip-text text-transparent' : 'text-emerald-700'}`}>
              SecureScanner
            </h1>
          )}
          <button 
            onClick={() => setSidebarCollapsed(!isSidebarCollapsed)}
            className={`w-8 h-8 flex items-center justify-center ${darkMode ? 'text-emerald-400 hover:bg-emerald-900/30' : 'text-emerald-600 hover:bg-emerald-100'} rounded-md transition-colors`}
            aria-label={isSidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            aria-expanded={!isSidebarCollapsed}
          >
            {isSidebarCollapsed ? (
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 5l7 7-7 7M5 5l7 7-7 7" />
              </svg>
            ) : (
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M11 19l-7-7 7-7m8 14l-7-7 7-7" />
              </svg>
            )}
          </button>
        </div>
        
        {/* Navigation Links with updated styling */}
        <nav className="flex-1 py-4">
          <ul className="space-y-2" role="menu">
            <li role="none">
              <button 
                onClick={() => setActivePage('scanner')}
                className={`flex items-center ${isSidebarCollapsed ? 'justify-center' : 'px-4'} py-2 w-full ${
                  activePage === 'scanner' 
                    ? darkMode ? 'bg-emerald-900/30 text-emerald-400' : 'bg-emerald-100 text-emerald-700'
                    : darkMode ? 'text-slate-400 hover:text-emerald-400 hover:bg-emerald-900/20' : 'text-gray-500 hover:text-emerald-600 hover:bg-emerald-50'
                } transition-colors`}
                role="menuitem"
                aria-current={activePage === 'scanner' ? 'page' : undefined}
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
                {!isSidebarCollapsed && <span className="ml-3">File Scanner</span>}
              </button>
            </li>
            <li role="none">
              <button 
                onClick={() => setActivePage('reports')}
                className={`flex items-center ${isSidebarCollapsed ? 'justify-center' : 'px-4'} py-2 w-full ${
                  activePage === 'reports' 
                    ? darkMode ? 'bg-emerald-900/30 text-emerald-400' : 'bg-emerald-100 text-emerald-700'
                    : darkMode ? 'text-slate-400 hover:text-emerald-400 hover:bg-emerald-900/20' : 'text-gray-500 hover:text-emerald-600 hover:bg-emerald-50'
                } transition-colors`}
                role="menuitem"
                aria-current={activePage === 'reports' ? 'page' : undefined}
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                {!isSidebarCollapsed && <span className="ml-3">Reports</span>}
            </button>
            </li>
            <li role="none">
              <button 
                onClick={() => setDarkMode(!darkMode)}
                className={`flex items-center ${isSidebarCollapsed ? 'justify-center' : 'px-4'} py-2 w-full ${
                  darkMode ? 'text-slate-400 hover:text-emerald-400 hover:bg-emerald-900/20' : 'text-gray-500 hover:text-emerald-600 hover:bg-emerald-50'
                } transition-colors`}
                role="menuitem"
                aria-pressed={darkMode}
              >
                {darkMode ? (
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
                  </svg>
                ) : (
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
                  </svg>
                )}
                {!isSidebarCollapsed && <span className="ml-3">{darkMode ? 'Light Mode' : 'Dark Mode'}</span>}
            </button>
            </li>
          </ul>
        </nav>
        
        {/* Security Status - simplified */}
        {!isSidebarCollapsed && (
          <div className={`p-4 border-t ${darkMode ? 'border-emerald-900/30' : 'border-gray-200'}`}>
            <div className={`rounded-lg ${darkMode ? 'bg-emerald-900/20 border-emerald-900/30' : 'bg-emerald-50 border-emerald-200'} p-3 border`}>
              <div className="flex items-center justify-between">
                <h3 className={`text-xs uppercase ${darkMode ? 'text-emerald-400' : 'text-emerald-700'} font-semibold`}>Files</h3>
                <span 
                  className={`w-2 h-2 rounded-full ${files.length > 0 ? 'bg-emerald-500' : 'bg-gray-400'}`}
                  aria-hidden="true"
                ></span>
              </div>
              <div className="mt-2">
                <div className="flex items-center justify-between text-xs text-slate-400">
                  <span>Total files:</span>
                  <span className={darkMode ? 'text-emerald-400' : 'text-emerald-600'}>{files.length}</span>
                </div>
                <div className="flex items-center justify-between text-xs text-slate-400 mt-1">
                  <span>Scan level:</span>
                  <span className={darkMode ? 'text-emerald-400' : 'text-emerald-600'}>{scanLevel.toUpperCase()}</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col">
        {/* Header - simplified */}
        <div className={`border-b ${darkMode ? 'border-emerald-800/30 backdrop-blur-md bg-black/40' : 'border-gray-200 bg-white/80'} p-4 shadow-sm z-10`}>
          <div className="flex items-center justify-between">
            <h1 className={`text-xl font-bold ${darkMode ? 'bg-gradient-to-r from-emerald-400 via-teal-400 to-cyan-500 bg-clip-text text-transparent' : 'text-emerald-700'}`}>
              Secure File Analyzer
            </h1>
            <div className="flex items-center gap-3">
              <span className={`text-sm ${darkMode ? 'text-slate-300' : 'text-gray-700'}`}>
                Basic Scan Mode
              </span>
            </div>
          </div>
        </div>

        {/* Main content - streamlined */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Files Tab */}
          <div className="flex-1 flex overflow-hidden relative">
            {/* Main Files List Area */}
            <div className={`transition-all duration-300 ${isFileDetailOpen ? 'w-1/2' : 'w-full'} overflow-y-auto p-5`}>
              {/* Upload Area - minimal design */}
              <div 
                ref={dropAreaRef}
                className={`${
                  darkMode 
                    ? 'bg-gradient-to-br from-slate-800/50 to-black/50 border-emerald-900/30' 
                    : 'bg-white border-gray-200'
                } backdrop-blur-md rounded-xl p-6 mb-6 border transition-all hover:border-emerald-500/50`}
                aria-labelledby="drop-area-title"
              >
                <div 
                  className={`${
                    darkMode
                      ? 'border-emerald-800/40 bg-black/30'
                      : 'border-emerald-200 bg-emerald-50/50'
                  } border-2 border-dashed rounded-xl p-8 text-center hover:border-emerald-500/50 transition-colors cursor-pointer group`}
                  onClick={() => fileInputRef.current?.click()}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      fileInputRef.current?.click();
                    }
                  }}
                  aria-label="Drop files here or click to upload"
                >
                  <div className="group-hover:scale-110 transition-transform duration-300">
                    <svg className={`w-14 h-14 mx-auto mb-3 ${darkMode ? 'text-emerald-500/70' : 'text-emerald-600'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                    </svg>
                  </div>
                  <p id="drop-area-title" className={`text-sm mb-2 font-medium ${darkMode ? 'text-emerald-300' : 'text-emerald-700'}`}>
                    Drop files for secure analysis
                  </p>
                  <p className={`text-xs mb-4 ${darkMode ? 'text-slate-500' : 'text-gray-500'}`}>
                    or click to browse
                  </p>
        </div>
      </div>

              {/* Files List - minimal card layout */}
              <div aria-live="polite">
              {files.length > 0 ? (
                  <div role="list" aria-label="Uploaded files" className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {files.map((file) => (
                    <div 
                      key={file.id} 
                        role="listitem"
                      className={`${
                        darkMode
                          ? 'bg-slate-800/40 border-emerald-900/30'
                          : 'bg-white border-gray-200'
                      } backdrop-blur-md rounded-lg p-4 border hover:border-emerald-500/50 transition-all cursor-pointer group`}
                      onClick={() => handleViewFileDetails(file)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            handleViewFileDetails(file);
                          }
                        }}
                        tabIndex={0}
                        aria-label={`File: ${file.name}, Size: ${file.size}, Status: ${file.status}`}
                    >
                      <div className="flex items-start">
                        <div className={`p-3 rounded-lg ${
                          darkMode 
                            ? 'bg-emerald-900/50 text-emerald-300 ring-1 ring-emerald-500/20 group-hover:bg-emerald-800/70' 
                            : 'bg-emerald-100 text-emerald-700'
                            } transition-colors`}
                            aria-hidden="true"
                          >
                          {getFileIcon(file.type)}
                        </div>
                        <div className="flex-1 min-w-0 ml-3">
                          <div className="flex items-start justify-between">
                            <p className={`text-sm font-medium truncate max-w-[200px] ${darkMode ? 'text-slate-300' : 'text-gray-700'}`}>
                              {file.name}
                            </p>
                            <button 
                              onClick={(e) => { 
                                e.stopPropagation();
                                removeFile(file.id);
                              }}
                              className={`p-1 rounded-full ${
                                darkMode
                                  ? 'hover:bg-slate-700/70 text-slate-400 hover:text-slate-300'
                                  : 'hover:bg-gray-100 text-gray-400 hover:text-gray-600'
                              } transition-colors opacity-0 group-hover:opacity-100`}
                                aria-label={`Remove ${file.name}`}
                            >
                                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                              </svg>
                            </button>
                          </div>
                          <div className="flex items-center gap-2 mt-1">
                            <span className={`text-xs ${darkMode ? 'text-slate-400' : 'text-gray-500'}`}>{file.size}</span>
                            <FileStatusBadge status={file.status} />
                          </div>
                          {(file.status === 'uploading' || file.status === 'processing') && (
                              <div 
                                className={`w-full ${darkMode ? 'bg-slate-700' : 'bg-gray-200'} rounded-full h-1.5 mt-2`}
                                role="progressbar" 
                                aria-valuenow={file.progress} 
                                aria-valuemin={0} 
                                aria-valuemax={100}
                              >
                              <div 
                                className="bg-gradient-to-r from-emerald-500 to-teal-500 h-1.5 rounded-full transition-all duration-300"
                                style={{ width: `${file.progress}%` }}
                              ></div>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                  <div className={`flex flex-col items-center justify-center h-48 ${darkMode ? 'text-slate-500' : 'text-gray-500'} mt-6`} aria-live="polite">
                    <svg className={`w-16 h-16 mb-3 ${darkMode ? 'text-emerald-500/20' : 'text-emerald-300/50'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  <p className="mb-1">No files to analyze</p>
                  <p className="text-xs">Upload files to begin</p>
                </div>
              )}
              </div>
            </div>
            
            {/* Simplified File Detail Panel */}
            {isFileDetailOpen && selectedFile && (
              <div 
                className={`w-1/2 border-l ${
                darkMode 
                  ? 'border-emerald-900/30 bg-gradient-to-br from-slate-950 to-black/90' 
                  : 'border-gray-200 bg-gray-50'
                } overflow-y-auto`}
                role="region" 
                aria-label="File details"
              >
                <div className={`sticky top-0 border-b ${
                  darkMode 
                    ? 'border-emerald-900/30 backdrop-blur-md bg-black/40' 
                    : 'border-gray-200 bg-white/90'
                  } p-4 flex items-center justify-between`}>
                  <h3 className={`text-lg font-medium ${darkMode ? 'text-slate-200' : 'text-gray-700'}`}>
                    Analysis Report
                  </h3>
                  <button 
                    onClick={handleCloseFileDetails}
                    className={`p-1.5 rounded-lg ${
                      darkMode 
                        ? 'hover:bg-slate-800/70 text-slate-400 hover:text-slate-300' 
                        : 'hover:bg-gray-100 text-gray-400 hover:text-gray-600'
                    } transition-colors`}
                    aria-label="Close file details"
                  >
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </button>
                </div>
                
                <div className="p-5 space-y-5">
                  {/* File info */}
                  <div className="flex items-center">
                    <div className={`p-4 rounded-xl ${
                      darkMode 
                        ? 'bg-emerald-900/30 text-emerald-300 ring-1 ring-emerald-500/20' 
                        : 'bg-emerald-100 text-emerald-700'
                      } mr-4`}
                      aria-hidden="true"
                    >
                      {getFileIcon(selectedFile.type)}
                    </div>
                    <div>
                      <h4 className={`text-lg font-medium ${darkMode ? 'text-slate-200' : 'text-gray-700'}`}>
                        {selectedFile.name}
                      </h4>
                      <div className={`flex items-center gap-2 mt-1 text-sm ${darkMode ? 'text-slate-400' : 'text-gray-500'}`}>
                        <span>{selectedFile.size}</span>
                        <span aria-hidden="true">•</span>
                        <span>{selectedFile.type.split('/')[1]?.toUpperCase() || 'UNKNOWN'}</span>
                      </div>
                    </div>
                  </div>
                  
                  {/* Threat Summary */}
                  {selectedFile.analysisReport && (
                    <>
                  <div className={`${
                    darkMode 
                      ? 'bg-slate-800/40 border-emerald-900/30' 
                      : 'bg-white border-gray-200'
                    } rounded-xl p-4 border`}>
                        <div className="flex justify-between items-center mb-3">
                          <h4 className={`text-sm font-medium ${darkMode ? 'text-slate-300' : 'text-gray-700'}`}>
                            Analysis Summary
                    </h4>
                          <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                            selectedFile.analysisReport.overallVerdict === 'clean' 
                              ? 'bg-emerald-100 text-emerald-800'
                              : selectedFile.analysisReport.overallVerdict === 'suspicious'
                              ? 'bg-amber-100 text-amber-800'
                              : 'bg-red-100 text-red-800'
                          }`}>
                            {selectedFile.analysisReport.overallVerdict.toUpperCase()}
                          </span>
                      </div>
                        
                        <div className="mb-3">
                          <div className="flex items-center justify-between text-sm mb-1">
                            <span className={darkMode ? 'text-slate-400' : 'text-gray-600'}>Threat Score</span>
                            <span className={`font-medium ${
                              selectedFile.analysisReport.threatScore < 30
                                ? darkMode ? 'text-emerald-400' : 'text-emerald-600'
                                : selectedFile.analysisReport.threatScore < 70
                                ? darkMode ? 'text-amber-400' : 'text-amber-600'
                                : darkMode ? 'text-red-400' : 'text-red-600'
                            }`}>
                              {selectedFile.analysisReport.threatScore}/100
                            </span>
                          </div>
                          <div 
                            className="w-full bg-gray-300 rounded-full h-2"
                            role="progressbar"
                            aria-valuemin={0}
                            aria-valuemax={100}
                            aria-valuenow={selectedFile.analysisReport.threatScore}
                          >
                            <div 
                              className={`h-2 rounded-full ${
                                selectedFile.analysisReport.threatScore < 30
                                  ? 'bg-emerald-500'
                                  : selectedFile.analysisReport.threatScore < 70
                                  ? 'bg-amber-500'
                                  : 'bg-red-500'
                              }`} 
                              style={{width: `${selectedFile.analysisReport.threatScore}%`}}
                            ></div>
                    </div>
                  </div>
                  
                        <div className="text-xs grid grid-cols-2 gap-2">
                          <div>
                            <span className={darkMode ? 'text-slate-400' : 'text-gray-500'}>Scan Date:</span>
                            <span className={`ml-1 ${darkMode ? 'text-slate-300' : 'text-gray-700'}`}>
                              {selectedFile.analysisReport.analyzedAt.toLocaleString()}
                            </span>
                          </div>
                          <div>
                            <span className={darkMode ? 'text-slate-400' : 'text-gray-500'}>Scan Level:</span>
                            <span className={`ml-1 ${darkMode ? 'text-slate-300' : 'text-gray-700'}`}>
                              {scanLevel.toUpperCase()}
                            </span>
                          </div>
                          <div>
                            <span className={darkMode ? 'text-slate-400' : 'text-gray-500'}>Detections:</span>
                            <span className={`ml-1 ${
                              selectedFile.analysisReport.staticAnalysis.positiveScans > 0
                                ? darkMode ? 'text-red-400' : 'text-red-600'
                                : darkMode ? 'text-slate-300' : 'text-gray-700'
                            }`}>
                              {selectedFile.analysisReport.staticAnalysis.positiveScans}/{selectedFile.analysisReport.staticAnalysis.totalScans}
                            </span>
                          </div>
                          {selectedFile.analysisReport.dynamicAnalysis?.summary.malwareFamily && (
                            <div>
                              <span className={darkMode ? 'text-slate-400' : 'text-gray-500'}>Malware Family:</span>
                              <span className={`ml-1 ${darkMode ? 'text-red-400' : 'text-red-600'} font-medium`}>
                                {selectedFile.analysisReport.dynamicAnalysis.summary.malwareFamily}
                              </span>
                            </div>
                          )}
                        </div>
                      </div>
                      
                      {/* Analysis Tabs */}
                      <div>
                        <div className="flex border-b border-gray-200 mb-4">
                          <button
                            className={`py-2 px-4 text-sm font-medium ${
                              activeReportTab === 'static'
                                ? darkMode 
                                  ? 'border-b-2 border-emerald-500 text-emerald-400'
                                  : 'border-b-2 border-emerald-500 text-emerald-700'
                                : darkMode
                                  ? 'text-slate-400 hover:text-slate-300'
                                  : 'text-gray-500 hover:text-gray-700'
                            }`}
                            onClick={() => setActiveReportTab('static')}
                            aria-selected={activeReportTab === 'static'}
                            role="tab"
                          >
                            Static Analysis
                    </button>
                          
                          {selectedFile.analysisReport.dynamicAnalysis && (
                            <button
                              className={`py-2 px-4 text-sm font-medium ${
                                activeReportTab === 'dynamic'
                                  ? darkMode 
                                    ? 'border-b-2 border-emerald-500 text-emerald-400'
                                    : 'border-b-2 border-emerald-500 text-emerald-700'
                                  : darkMode
                                    ? 'text-slate-400 hover:text-slate-300'
                                    : 'text-gray-500 hover:text-gray-700'
                              }`}
                              onClick={() => setActiveReportTab('dynamic')}
                              aria-selected={activeReportTab === 'dynamic'}
                              role="tab"
                            >
                              Dynamic Analysis
                            </button>
                          )}
                        </div>
                        
                        {/* Tab content - Static Analysis */}
                        <div className={`${activeReportTab === 'static' ? 'block' : 'hidden'} space-y-4`} role="tabpanel">
                          {/* File Hashes Section */}
                          <div className={`${
                      darkMode 
                              ? 'bg-slate-800/40 border-emerald-900/30' 
                              : 'bg-white border-gray-200'
                            } rounded-lg p-3 border text-xs`}
                          >
                            <h5 className={`text-xs font-medium mb-2 ${darkMode ? 'text-slate-300' : 'text-gray-700'}`}>
                              File Hashes
                            </h5>
                            <div className="grid grid-cols-1 gap-2">
                              <div className="flex justify-between">
                                <span className={darkMode ? 'text-slate-400' : 'text-gray-500'}>MD5:</span>
                                <span className={`font-mono ${darkMode ? 'text-slate-300' : 'text-gray-700'}`}>
                                  {selectedFile.analysisReport.staticAnalysis.fileInfo.md5}
                                </span>
                              </div>
                              <div className="flex justify-between">
                                <span className={darkMode ? 'text-slate-400' : 'text-gray-500'}>SHA-1:</span>
                                <span className={`font-mono ${darkMode ? 'text-slate-300' : 'text-gray-700'}`}>
                                  {selectedFile.analysisReport.staticAnalysis.fileInfo.sha1}
                                </span>
                              </div>
                              <div className="flex justify-between">
                                <span className={darkMode ? 'text-slate-400' : 'text-gray-500'}>SHA-256:</span>
                                <span className={`font-mono ${darkMode ? 'text-slate-300' : 'text-gray-700'}`}>
                                  {selectedFile.analysisReport.staticAnalysis.fileInfo.sha256}
                                </span>
                              </div>
                            </div>
                          </div>
                          
                          {/* VirusTotal Results */}
                          <div className={`${
                            darkMode 
                              ? 'bg-slate-800/40 border-emerald-900/30' 
                              : 'bg-white border-gray-200'
                            } rounded-lg p-3 border`}
                          >
                            <div className="flex justify-between items-center mb-2">
                              <h5 className={`text-xs font-medium ${darkMode ? 'text-slate-300' : 'text-gray-700'}`}>
                                VirusTotal Results
                              </h5>
                              <span className={`text-xs ${
                                selectedFile.analysisReport.staticAnalysis.virusTotal.positives > 0
                                  ? darkMode ? 'text-red-400' : 'text-red-600'
                                  : darkMode ? 'text-emerald-400' : 'text-emerald-600'
                              }`}>
                                {selectedFile.analysisReport.staticAnalysis.virusTotal.positives} / {selectedFile.analysisReport.staticAnalysis.virusTotal.total} detections
                              </span>
                            </div>
                            
                            <div className="space-y-2 mt-3">
                              {Object.entries(selectedFile.analysisReport.staticAnalysis.virusTotal.scans)
                                .map(([engine, result], index) => (
                                  <div 
                                    key={index} 
                                    className={`flex justify-between items-center p-2 rounded-md ${
                                      result.detected
                                        ? darkMode ? 'bg-red-900/20' : 'bg-red-50'
                                        : darkMode ? 'bg-slate-700/30' : 'bg-gray-50'
                                    }`}
                                  >
                                    <div className="flex items-center">
                                      <div className={`w-2 h-2 rounded-full mr-2 ${
                                        result.detected
                                          ? 'bg-red-500'
                                          : 'bg-emerald-500'
                                      }`}></div>
                                      <span className={`text-xs ${darkMode ? 'text-slate-300' : 'text-gray-700'}`}>
                                        {engine}
                                      </span>
                                    </div>
                                    <span className={`text-xs ${
                                      result.detected
                                        ? darkMode ? 'text-red-400 font-medium' : 'text-red-600 font-medium'
                                        : darkMode ? 'text-slate-400' : 'text-gray-500'
                                    }`}>
                                      {result.detected ? result.result : 'Clean'}
                                    </span>
                                  </div>
                                ))}
                            </div>
                            
                            <a 
                              href={selectedFile.analysisReport.staticAnalysis.virusTotal.permalink} 
                              target="_blank" 
                              rel="noopener noreferrer"
                              className={`mt-3 text-xs flex items-center ${
                                darkMode ? 'text-emerald-400 hover:text-emerald-300' : 'text-emerald-600 hover:text-emerald-700'
                              }`}
                            >
                              View full report on VirusTotal
                              <svg className="w-3 h-3 ml-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                              </svg>
                            </a>
                          </div>
                          
                          {/* Static Analysis Signatures */}
                          {selectedFile.analysisReport.staticAnalysis.signatures.length > 0 && (
                            <div className={`${
                              darkMode 
                                ? 'bg-slate-800/40 border-emerald-900/30' 
                                : 'bg-white border-gray-200'
                              } rounded-lg p-3 border`}
                            >
                              <h5 className={`text-xs font-medium mb-2 ${darkMode ? 'text-slate-300' : 'text-gray-700'}`}>
                                Detected Signatures
                              </h5>
                              
                              <div className="space-y-2">
                                {selectedFile.analysisReport.staticAnalysis.signatures.map((signature, index) => (
                                  <div 
                                    key={index} 
                                    className={`p-2 rounded-md ${
                                      signature.severity === 'critical' || signature.severity === 'high'
                                        ? darkMode ? 'bg-red-900/20' : 'bg-red-50'
                                        : signature.severity === 'medium'
                                        ? darkMode ? 'bg-amber-900/20' : 'bg-amber-50'
                                        : darkMode ? 'bg-slate-700/30' : 'bg-gray-50'
                                    }`}
                                  >
                                    <div className="flex justify-between">
                                      <span className={`text-xs font-medium ${
                                        signature.severity === 'critical' || signature.severity === 'high'
                                          ? darkMode ? 'text-red-400' : 'text-red-600'
                                          : signature.severity === 'medium'
                                          ? darkMode ? 'text-amber-400' : 'text-amber-600'
                                          : darkMode ? 'text-slate-300' : 'text-gray-700'
                                      }`}>
                                        {signature.name}
                                      </span>
                                      <span className={`text-xs px-2 rounded-full ${
                                        signature.severity === 'critical'
                                          ? 'bg-red-200 text-red-800'
                                          : signature.severity === 'high'
                                          ? 'bg-red-100 text-red-800'
                                          : signature.severity === 'medium'
                                          ? 'bg-amber-100 text-amber-800'
                                          : 'bg-gray-100 text-gray-800'
                                      }`}>
                                        {signature.severity.toUpperCase()}
                                      </span>
                                    </div>
                                    <p className={`text-xs mt-1 ${darkMode ? 'text-slate-400' : 'text-gray-500'}`}>
                                      {signature.description}
                                    </p>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                          
                          {/* Dynamic Analysis Button */}
                          {selectedFile.analysisReport?.dynamicAnalysis === undefined && (
                            <div className={`${
                              darkMode 
                                ? 'bg-slate-800/40 border-emerald-900/30' 
                                : 'bg-white border-gray-200'
                              } rounded-lg p-4 border text-center`}
                            >
                              <p className={`text-sm mb-3 ${darkMode ? 'text-slate-300' : 'text-gray-700'}`}>
                                No dynamic analysis has been performed on this file yet.
                              </p>
                              <button
                                onClick={() => runDynamicAnalysis(selectedFile.id, selectedFile.name)}
                                className={`py-2 px-4 ${
                                  darkMode 
                                    ? 'bg-gradient-to-r from-emerald-600 to-teal-600' 
                                    : 'bg-emerald-600'
                                  } text-white rounded-lg transition-colors hover:opacity-90 text-sm font-medium inline-flex items-center`}
                              >
                                <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                                Run Dynamic Analysis
                    </button>
                  </div>
                          )}
                </div>
              </div>
                    </>
                  )}
                  
                  {/* Tab content - Dynamic Analysis */}
                  {selectedFile.analysisReport?.dynamicAnalysis && (
                    <div className={`${activeReportTab === 'dynamic' ? 'block' : 'hidden'} space-y-4`} role="tabpanel">
                      {/* Behavioral Summary */}
                      <div className={`${
                        darkMode 
                          ? 'bg-slate-800/40 border-emerald-900/30' 
                          : 'bg-white border-gray-200'
                        } rounded-lg p-3 border`}
                      >
                        <h5 className={`text-xs font-medium mb-2 ${darkMode ? 'text-slate-300' : 'text-gray-700'}`}>
                          Behavioral Summary
                        </h5>
                        
                        <div className="space-y-2 text-xs">
                          <div className="flex justify-between">
                            <span className={darkMode ? 'text-slate-400' : 'text-gray-500'}>Execution Time:</span>
                            <span className={darkMode ? 'text-slate-300' : 'text-gray-700'}>
                             {selectedFile.analysisReport?.dynamicAnalysis?.duration ?? 'N/A'} seconds
                            </span>
                          </div>
                          
                          <div className="flex justify-between">
                            <span className={darkMode ? 'text-slate-400' : 'text-gray-500'}>Verdict:</span>
                            <span className={`font-medium ${
                             selectedFile.analysisReport?.dynamicAnalysis?.summary?.verdict === 'clean'
                                ? darkMode ? 'text-emerald-400' : 'text-emerald-600'
                               : selectedFile.analysisReport?.dynamicAnalysis?.summary?.verdict === 'suspicious'
                                ? darkMode ? 'text-amber-400' : 'text-amber-600'
                                : darkMode ? 'text-red-400' : 'text-red-600'
                            }`}>
                             {selectedFile.analysisReport?.dynamicAnalysis?.summary?.verdict?.toUpperCase() ?? 'UNKNOWN'}
                            </span>
                          </div>
                          
                          {selectedFile.analysisReport.dynamicAnalysis.summary.malwareFamily && (
                            <div className="flex justify-between">
                              <span className={darkMode ? 'text-slate-400' : 'text-gray-500'}>Malware Family:</span>
                              <span className={`font-medium ${darkMode ? 'text-red-400' : 'text-red-600'}`}>
                                {selectedFile.analysisReport.dynamicAnalysis.summary.malwareFamily}
                              </span>
                            </div>
                          )}
                        </div>
                        
                        {selectedFile.analysisReport.dynamicAnalysis.summary.behaviorCategories.length > 0 && (
                          <div className="mt-3">
                            <h6 className={`text-xs font-medium mb-2 ${darkMode ? 'text-slate-400' : 'text-gray-600'}`}>
                              Behavior Categories:
                            </h6>
                            <div className="flex flex-wrap gap-1">
                              {selectedFile.analysisReport.dynamicAnalysis.summary.behaviorCategories.map((category, index) => (
                                <span key={index} className={`text-xs px-2 py-0.5 rounded-full ${
                                  selectedFile.analysisReport.dynamicAnalysis.summary.verdict === 'malicious'
                                    ? 'bg-red-100 text-red-800'
                                    : selectedFile.analysisReport.dynamicAnalysis.summary.verdict === 'suspicious'
                                    ? 'bg-amber-100 text-amber-800'
                                    : 'bg-emerald-100 text-emerald-800'
                                }`}>
                                  {category}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                        
                        {selectedFile.analysisReport.dynamicAnalysis.summary.mitreTactics.length > 0 && (
                          <div className="mt-3">
                            <h6 className={`text-xs font-medium mb-2 ${darkMode ? 'text-slate-400' : 'text-gray-600'}`}>
                              MITRE ATT&CK Tactics:
                            </h6>
                            <div className="space-y-2">
                              {selectedFile.analysisReport.dynamicAnalysis.summary.mitreTactics.map((tactic, index) => (
                                <div key={index} className={`p-2 rounded-md ${
                                  darkMode ? 'bg-red-900/20' : 'bg-red-50'
                                }`}>
                                  <div className="flex justify-between">
                                    <span className={`text-xs font-medium ${darkMode ? 'text-red-400' : 'text-red-600'}`}>
                                      {tactic.name} ({tactic.id})
                                    </span>
                                  </div>
                                  <p className={`text-xs mt-1 ${darkMode ? 'text-slate-400' : 'text-gray-500'}`}>
                                    {tactic.description}
                                  </p>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                      
                      {/* Process Activity */}
                      <div className={`${
                        darkMode 
                          ? 'bg-slate-800/40 border-emerald-900/30' 
                          : 'bg-white border-gray-200'
                        } rounded-lg p-3 border`}
                      >
                        <h5 className={`text-xs font-medium mb-2 ${darkMode ? 'text-slate-300' : 'text-gray-700'}`}>
                          Process Activity
                        </h5>
                        
                        <div className="space-y-2">
                          {selectedFile.analysisReport.dynamicAnalysis.processes.map((process, index) => (
                            <div 
                              key={index} 
                              className={`p-2 rounded-md ${
                                process.isMalicious
                                  ? darkMode ? 'bg-red-900/20' : 'bg-red-50'
                                  : darkMode ? 'bg-slate-700/30' : 'bg-gray-50'
                              }`}
                            >
                              <div className="flex justify-between">
                                <span className={`text-xs font-medium ${process.isMalicious 
                                  ? darkMode ? 'text-red-400' : 'text-red-600' 
                                  : darkMode ? 'text-slate-300' : 'text-gray-700'
                                }`}>
                                  {process.name} (PID: {process.pid})
                                </span>
                                {process.isMalicious && (
                                  <span className="text-xs px-2 rounded-full bg-red-100 text-red-800">
                                    MALICIOUS
                                  </span>
                                )}
                              </div>
                              <p className={`text-xs mt-1 ${darkMode ? 'text-slate-400' : 'text-gray-500'}`}>
                                Path: {process.path}
                              </p>
                              <p className={`text-xs mt-1 ${darkMode ? 'text-slate-400' : 'text-gray-500'}`}>
                                Command Line: {process.commandLine}
                              </p>
                            </div>
                          ))}
                        </div>
                      </div>
                      
                      {/* Network Activity */}
                      {selectedFile.analysisReport.dynamicAnalysis.networkActivity.length > 0 && (
                        <div className={`${
                          darkMode 
                            ? 'bg-slate-800/40 border-emerald-900/30' 
                            : 'bg-white border-gray-200'
                          } rounded-lg p-3 border`}
                        >
                          <h5 className={`text-xs font-medium mb-2 ${darkMode ? 'text-slate-300' : 'text-gray-700'}`}>
                            Network Activity
                          </h5>
                          
                          <div className="space-y-2">
                            {selectedFile.analysisReport.dynamicAnalysis.networkActivity.map((activity, index) => (
                              <div 
                                key={index} 
                                className={`p-2 rounded-md ${
                                  activity.isMalicious
                                    ? darkMode ? 'bg-red-900/20' : 'bg-red-50'
                                    : darkMode ? 'bg-slate-700/30' : 'bg-gray-50'
                                }`}
                              >
                                <div className="flex justify-between">
                                  <span className={`text-xs font-medium ${
                                    activity.isMalicious 
                                      ? darkMode ? 'text-red-400' : 'text-red-600' 
                                      : darkMode ? 'text-slate-300' : 'text-gray-700'
                                  }`}>
                                    {activity.protocol} Connection {activity.remoteHostname && `to ${activity.remoteHostname}`}
                                  </span>
                                  {activity.isMalicious && (
                                    <span className="text-xs px-2 rounded-full bg-red-100 text-red-800">
                                      SUSPICIOUS
                                    </span>
                                  )}
                                </div>
                                <p className={`text-xs mt-1 ${darkMode ? 'text-slate-400' : 'text-gray-500'}`}>
                                  {activity.localIp}:{activity.localPort} → {activity.remoteIp}:{activity.remotePort}
                                </p>
                                {activity.isMalicious && activity.maliciousReason && (
                                  <p className={`text-xs mt-1 ${darkMode ? 'text-red-400' : 'text-red-600'}`}>
                                    {activity.maliciousReason}
                                  </p>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      
                      {/* File System Activity */}
                      {selectedFile.analysisReport.dynamicAnalysis.fileSystemActivity.length > 0 && (
                        <div className={`${
                          darkMode 
                            ? 'bg-slate-800/40 border-emerald-900/30' 
                            : 'bg-white border-gray-200'
                          } rounded-lg p-3 border`}
                        >
                          <h5 className={`text-xs font-medium mb-2 ${darkMode ? 'text-slate-300' : 'text-gray-700'}`}>
                            File System Activity
                          </h5>
                          
                          <div className="space-y-2">
                            {selectedFile.analysisReport.dynamicAnalysis.fileSystemActivity.map((activity, index) => (
                              <div 
                                key={index} 
                                className={`p-2 rounded-md ${
                                  activity.isMalicious
                                    ? darkMode ? 'bg-red-900/20' : 'bg-red-50'
                                    : darkMode ? 'bg-slate-700/30' : 'bg-gray-50'
                                }`}
                              >
                                <div className="flex justify-between">
                                  <span className={`text-xs font-medium ${
                                    activity.isMalicious 
                                      ? darkMode ? 'text-red-400' : 'text-red-600' 
                                      : darkMode ? 'text-slate-300' : 'text-gray-700'
                                  }`}>
                                    {activity.operation.toUpperCase()} {activity.path.split('\\').pop()}
                                  </span>
                                  {activity.isMalicious && (
                                    <span className="text-xs px-2 rounded-full bg-red-100 text-red-800">
                                      SUSPICIOUS
                                    </span>
                                  )}
                                </div>
                                <p className={`text-xs mt-1 ${darkMode ? 'text-slate-400' : 'text-gray-500'}`}>
                                  Path: {activity.path}
                                </p>
                                <p className={`text-xs mt-1 ${darkMode ? 'text-slate-400' : 'text-gray-500'}`}>
                                  Process: {activity.processName} (PID: {activity.pid})
                                </p>
                                {activity.isMalicious && activity.maliciousReason && (
                                  <p className={`text-xs mt-1 ${darkMode ? 'text-red-400' : 'text-red-600'}`}>
                                    {activity.maliciousReason}
                                  </p>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      
                      {/* Registry Activity */}
                      {selectedFile.analysisReport.dynamicAnalysis.registryActivity.length > 0 && (
                        <div className={`${
                          darkMode 
                            ? 'bg-slate-800/40 border-emerald-900/30' 
                            : 'bg-white border-gray-200'
                          } rounded-lg p-3 border`}
                        >
                          <h5 className={`text-xs font-medium mb-2 ${darkMode ? 'text-slate-300' : 'text-gray-700'}`}>
                            Registry Activity
                          </h5>
                          
                          <div className="space-y-2">
                            {selectedFile.analysisReport.dynamicAnalysis.registryActivity.map((activity, index) => (
                              <div 
                                key={index} 
                                className={`p-2 rounded-md ${
                                  activity.isMalicious
                                    ? darkMode ? 'bg-red-900/20' : 'bg-red-50'
                                    : darkMode ? 'bg-slate-700/30' : 'bg-gray-50'
                                }`}
                              >
                                <div className="flex justify-between">
                                  <span className={`text-xs font-medium ${
                                    activity.isMalicious 
                                      ? darkMode ? 'text-red-400' : 'text-red-600' 
                                      : darkMode ? 'text-slate-300' : 'text-gray-700'
                                  }`}>
                                    {activity.operation.toUpperCase()} {activity.key.split('\\').pop()}
                                  </span>
                                  {activity.isMalicious && (
                                    <span className="text-xs px-2 rounded-full bg-red-100 text-red-800">
                                      MALICIOUS
                                    </span>
                                  )}
                                </div>
                                <p className={`text-xs mt-1 ${darkMode ? 'text-slate-400' : 'text-gray-500'}`}>
                                  Key: {activity.key}
                                </p>
                                {activity.value && (
                                  <p className={`text-xs mt-1 ${darkMode ? 'text-slate-400' : 'text-gray-500'}`}>
                                    Value: {activity.value}
                                  </p>
                                )}
                                {activity.data && (
                                  <p className={`text-xs mt-1 ${darkMode ? 'text-slate-400' : 'text-gray-500'}`}>
                                    Data: {activity.data}
                                  </p>
                                )}
                                {activity.isMalicious && activity.maliciousReason && (
                                  <p className={`text-xs mt-1 ${darkMode ? 'text-red-400' : 'text-red-600'}`}>
                                    {activity.maliciousReason}
                                  </p>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
      </div>

        {/* Simple footer */}
        <div className={`border-t ${
          darkMode 
            ? 'border-emerald-900/30 backdrop-blur-md bg-black/40' 
            : 'border-gray-200 bg-white/80'
          } p-4`}>
          <div className="flex gap-3 items-center justify-center">
            <button
              onClick={() => fileInputRef.current?.click()}
              className={`py-3 px-6 ${
                darkMode 
                  ? 'bg-gradient-to-r from-emerald-600 to-teal-600' 
                  : 'bg-emerald-600'
                } text-white rounded-lg transition-colors hover:opacity-90 flex items-center justify-center font-medium`}
              aria-label="Select files to upload"
            >
              <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
              </svg>
              Select Files
            </button>
            
            <button 
              onClick={runFullScan} 
              disabled={files.length === 0}
              className={`py-3 px-6 flex items-center justify-center font-medium rounded-lg ${
                files.length === 0 
                  ? darkMode ? 'bg-slate-800/60 text-slate-500 cursor-not-allowed' : 'bg-gray-100 text-gray-400 cursor-not-allowed'
                  : darkMode ? 'bg-emerald-600 text-white hover:bg-emerald-700' : 'bg-emerald-600 text-white hover:bg-emerald-700'
              }`}
              aria-label="Scan all files"
            >
              <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              Scan All Files
            </button>
            
            <input
              type="file"
              onChange={handleFileChange}
              ref={fileInputRef}
              className="hidden"
              multiple
              aria-label="File upload"
            />
          </div>
            </div>
      </div>
    </div>
  )
} 

// Helper functions
const formatTime = (date: Date): string => {
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

const getFileIcon = (fileType: string) => {
  if (fileType.includes('image')) {
    return (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
      </svg>
    )
  } else if (fileType.includes('pdf')) {
    return (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
      </svg>
    )
  } else if (fileType.includes('spreadsheet') || fileType.includes('excel') || fileType.includes('csv')) {
    return (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 10h18M3 14h18m-9-4v8m-7 0h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z" />
      </svg>
    )
  } else if (fileType.includes('document') || fileType.includes('word')) {
    return (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
      </svg>
    )
  } else if (fileType.includes('zip') || fileType.includes('compressed')) {
    return (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4" />
      </svg>
    )
  } else if (fileType.includes('javascript') || fileType.includes('typescript') || fileType.includes('code')) {
    return (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
      </svg>
    )
  } else {
    return (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
      </svg>
    )
  }
} 