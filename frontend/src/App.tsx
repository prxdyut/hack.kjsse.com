import { Routes, Route, Link } from 'react-router-dom'
import Chat from './components/Chat'

function App() {
  return (
    <div className="flex h-screen bg-dark">
      {/* Main Content */}
      <div className="flex-1 overflow-hidden">
        <Routes>
          <Route path="/" element={<Chat />} />
          <Route path="/chat" element={<Chat />} />
          <Route path="/categories" element={<div className="p-4 text-white">Categories Page</div>} />
        </Routes>
      </div>
    </div>
  )
}

export default App
