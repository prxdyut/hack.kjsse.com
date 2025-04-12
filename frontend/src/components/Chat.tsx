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
}

interface Message {
  id: number
  text: string
  sender: 'user' | 'assistant'
  files?: CustomFile[]
  timestamp: Date
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
  const [scanLevel, setScanLevel] = useState<'basic' | 'deep' | 'forensic'>('basic')
  const [darkMode, setDarkMode] = useState(true)
  
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
          <div className="text-xs text-cyan-400 flex items-center">
            <svg className="w-3 h-3 mr-1 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            Uploading...
          </div>
        )
      case 'processing':
        return (
          <div className="text-xs text-amber-400 flex items-center">
            <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            Scanning...
          </div>
        )
      case 'completed':
        return (
          <div className="text-xs text-emerald-400 flex items-center">
            <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            Secured
          </div>
        )
      case 'error':
        return (
          <div className="text-xs text-red-400 flex items-center">
            <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            Failed
          </div>
        )
      default:
        return null
    }
  }

  const handleScanLevelChange = (level: 'basic' | 'deep' | 'forensic') => {
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
      const timeToComplete = scanLevel === 'basic' ? 3000 : scanLevel === 'deep' ? 5000 : 8000
      
      setTimeout(() => {
        clearInterval(interval)
        setFiles(prev => 
          prev.map(f => 
            f.id === file.id ? { ...f, status: 'completed', progress: 100 } : f
          )
        )
      }, timeToComplete)
    })
  }

  return (
    <div className={`flex h-screen ${darkMode ? 'bg-gradient-to-tr from-slate-950 via-gray-900 to-slate-900' : 'bg-gradient-to-tr from-gray-100 to-gray-200'}`}>
      {/* Sidebar */}
      <div className={`${isSidebarCollapsed ? 'w-16' : 'w-64'} ${darkMode ? 'bg-black/50 border-emerald-900/30' : 'bg-white/80 border-gray-200'} backdrop-blur-md border-r flex flex-col transition-all duration-300 ease-in-out`}>
        
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
          >
            {isSidebarCollapsed ? (
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 5l7 7-7 7M5 5l7 7-7 7" />
              </svg>
            ) : (
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M11 19l-7-7 7-7m8 14l-7-7 7-7" />
              </svg>
            )}
          </button>
        </div>
        
        {/* Navigation Links with updated styling */}
        <nav className="flex-1 py-4">
          <ul className="space-y-2">
            <li>
              <button 
                onClick={() => setActivePage('scanner')}
                className={`flex items-center ${isSidebarCollapsed ? 'justify-center' : 'px-4'} py-2 w-full ${
                  activePage === 'scanner' 
                    ? darkMode ? 'bg-emerald-900/30 text-emerald-400' : 'bg-emerald-100 text-emerald-700'
                    : darkMode ? 'text-slate-400 hover:text-emerald-400 hover:bg-emerald-900/20' : 'text-gray-500 hover:text-emerald-600 hover:bg-emerald-50'
                } transition-colors`}
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
                {!isSidebarCollapsed && <span className="ml-3">File Scanner</span>}
              </button>
            </li>
            <li>
              <button 
                onClick={() => setActivePage('reports')}
                className={`flex items-center ${isSidebarCollapsed ? 'justify-center' : 'px-4'} py-2 w-full ${
                  activePage === 'reports' 
                    ? darkMode ? 'bg-emerald-900/30 text-emerald-400' : 'bg-emerald-100 text-emerald-700'
                    : darkMode ? 'text-slate-400 hover:text-emerald-400 hover:bg-emerald-900/20' : 'text-gray-500 hover:text-emerald-600 hover:bg-emerald-50'
                } transition-colors`}
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                {!isSidebarCollapsed && <span className="ml-3">Reports</span>}
            </button>
            </li>
            <li>
              <button 
                onClick={() => setDarkMode(!darkMode)}
                className={`flex items-center ${isSidebarCollapsed ? 'justify-center' : 'px-4'} py-2 w-full ${
                  darkMode ? 'text-slate-400 hover:text-emerald-400 hover:bg-emerald-900/20' : 'text-gray-500 hover:text-emerald-600 hover:bg-emerald-50'
                } transition-colors`}
              >
                {darkMode ? (
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
                  </svg>
                ) : (
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
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
                <span className={`w-2 h-2 rounded-full ${files.length > 0 ? 'bg-emerald-500' : 'bg-gray-400'}`}></span>
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
              <select 
                value={scanLevel} 
                onChange={(e) => handleScanLevelChange(e.target.value as 'basic' | 'deep' | 'forensic')}
                className={`text-sm px-3 py-1.5 rounded-lg ${
                  darkMode 
                    ? 'bg-slate-800/80 text-slate-200 border border-emerald-900/30' 
                    : 'bg-white text-gray-700 border border-gray-200'
                }`}
              >
                <option value="basic">Basic Scan</option>
                <option value="deep">Deep Scan</option>
                <option value="forensic">Forensic Analysis</option>
              </select>
              
              <button 
                onClick={runFullScan} 
                disabled={files.length === 0}
                className={`text-sm px-3 py-1.5 rounded-lg flex items-center ${
                  files.length === 0 
                    ? darkMode ? 'bg-slate-800/60 text-slate-500 cursor-not-allowed' : 'bg-gray-100 text-gray-400 cursor-not-allowed'
                    : darkMode ? 'bg-emerald-600 text-white hover:bg-emerald-700' : 'bg-emerald-600 text-white hover:bg-emerald-700'
                }`}
              >
                <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                Scan All Files
            </button>
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
              >
                <div 
                  className={`${
                    darkMode
                      ? 'border-emerald-800/40 bg-black/30'
                      : 'border-emerald-200 bg-emerald-50/50'
                  } border-2 border-dashed rounded-xl p-8 text-center hover:border-emerald-500/50 transition-colors cursor-pointer group`}
                  onClick={() => fileInputRef.current?.click()}
                >
                  <div className="group-hover:scale-110 transition-transform duration-300">
                    <svg className={`w-14 h-14 mx-auto mb-3 ${darkMode ? 'text-emerald-500/70' : 'text-emerald-600'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                    </svg>
                  </div>
                  <p className={`text-sm mb-2 font-medium ${darkMode ? 'text-emerald-300' : 'text-emerald-700'}`}>
                    Drop files for secure analysis
                  </p>
                  <p className={`text-xs mb-4 ${darkMode ? 'text-slate-500' : 'text-gray-500'}`}>
                    or click to browse
                  </p>
        </div>
      </div>

              {/* Files List - minimal card layout */}
              {files.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {files.map((file) => (
                    <div 
                      key={file.id} 
                      className={`${
                        darkMode
                          ? 'bg-slate-800/40 border-emerald-900/30'
                          : 'bg-white border-gray-200'
                      } backdrop-blur-md rounded-lg p-4 border hover:border-emerald-500/50 transition-all cursor-pointer group`}
                      onClick={() => handleViewFileDetails(file)}
                    >
                      <div className="flex items-start">
                        <div className={`p-3 rounded-lg ${
                          darkMode 
                            ? 'bg-emerald-900/50 text-emerald-300 ring-1 ring-emerald-500/20 group-hover:bg-emerald-800/70' 
                            : 'bg-emerald-100 text-emerald-700'
                          } transition-colors`}>
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
                            >
                              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                              </svg>
                            </button>
                          </div>
                          <div className="flex items-center gap-2 mt-1">
                            <span className={`text-xs ${darkMode ? 'text-slate-400' : 'text-gray-500'}`}>{file.size}</span>
                            <FileStatusBadge status={file.status} />
                          </div>
                          {(file.status === 'uploading' || file.status === 'processing') && (
                            <div className={`w-full ${darkMode ? 'bg-slate-700' : 'bg-gray-200'} rounded-full h-1.5 mt-2`}>
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
                <div className={`flex flex-col items-center justify-center h-48 ${darkMode ? 'text-slate-500' : 'text-gray-500'} mt-6`}>
                  <svg className={`w-16 h-16 mb-3 ${darkMode ? 'text-emerald-500/20' : 'text-emerald-300/50'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  <p className="mb-1">No files to analyze</p>
                  <p className="text-xs">Upload files to begin</p>
                </div>
              )}
            </div>
            
            {/* Simplified File Detail Panel */}
            {isFileDetailOpen && selectedFile && (
              <div className={`w-1/2 border-l ${
                darkMode 
                  ? 'border-emerald-900/30 bg-gradient-to-br from-slate-950 to-black/90' 
                  : 'border-gray-200 bg-gray-50'
              } overflow-y-auto`}>
                <div className={`sticky top-0 border-b ${
                  darkMode 
                    ? 'border-emerald-900/30 backdrop-blur-md bg-black/40' 
                    : 'border-gray-200 bg-white/90'
                  } p-4 flex items-center justify-between`}>
                  <h3 className={`text-lg font-medium ${darkMode ? 'text-slate-200' : 'text-gray-700'}`}>
                    Analysis
                  </h3>
                  <button 
                    onClick={handleCloseFileDetails}
                    className={`p-1.5 rounded-lg ${
                      darkMode 
                        ? 'hover:bg-slate-800/70 text-slate-400 hover:text-slate-300' 
                        : 'hover:bg-gray-100 text-gray-400 hover:text-gray-600'
                    } transition-colors`}
                  >
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
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
                      } mr-4`}>
                      {getFileIcon(selectedFile.type)}
                    </div>
                    <div>
                      <h4 className={`text-lg font-medium ${darkMode ? 'text-slate-200' : 'text-gray-700'}`}>
                        {selectedFile.name}
                      </h4>
                      <div className={`flex items-center gap-2 mt-1 text-sm ${darkMode ? 'text-slate-400' : 'text-gray-500'}`}>
                        <span>{selectedFile.size}</span>
                        <span>•</span>
                        <span>{selectedFile.type.split('/')[1]?.toUpperCase() || 'UNKNOWN'}</span>
                      </div>
                    </div>
                  </div>
                  
                  {/* Security Score - simple meter */}
                  <div className={`${
                    darkMode 
                      ? 'bg-slate-800/40 border-emerald-900/30' 
                      : 'bg-white border-gray-200'
                    } rounded-xl p-4 border`}>
                    <h4 className={`text-sm font-medium ${darkMode ? 'text-slate-300' : 'text-gray-700'} mb-3`}>
                      Security Score
                    </h4>
                    <div className="flex items-center">
                      <div className="w-full bg-gray-300 rounded-full h-6">
                        <div className="bg-gradient-to-r from-emerald-500 to-teal-500 h-6 rounded-full" style={{width: '92%'}}></div>
                      </div>
                      <span className={`ml-3 font-bold ${darkMode ? 'text-emerald-400' : 'text-emerald-700'}`}>92%</span>
                    </div>
                  </div>
                  
                  {/* Actions */}
                  <div className="flex gap-3">
                    <button className="w-full py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg transition-colors text-sm font-medium">
                      Download Secure Copy
                    </button>
                    <button className={`w-full py-2.5 ${
                      darkMode 
                        ? 'bg-slate-700/50 hover:bg-slate-700 text-slate-300' 
                        : 'bg-gray-200 hover:bg-gray-300 text-gray-700'
                      } rounded-lg transition-colors text-sm`}>
                      Delete
                    </button>
                  </div>
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
              className={`py-3 px-8 ${
                darkMode 
                  ? 'bg-gradient-to-r from-emerald-600 to-teal-600' 
                  : 'bg-emerald-600'
                } text-white rounded-lg transition-colors hover:opacity-90 flex items-center justify-center font-medium`}
            >
              <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
              </svg>
              Select Files
            </button>
            
            <input
              type="file"
              onChange={handleFileChange}
              ref={fileInputRef}
              className="hidden"
              multiple
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