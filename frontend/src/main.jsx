import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.jsx';
import './index.css';
import { AuthProvider } from './context/AuthContext.jsx';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  componentDidCatch(error, errorInfo) {
    console.error('HHH ErrorBoundary caught:', error, errorInfo);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="p-8 text-red-400 bg-obsidian-950 min-h-screen font-mono flex flex-col justify-center items-center">
          <div className="max-w-2xl w-full p-6 bg-graphite-900 border border-red-500/40 rounded-2xl space-y-4 shadow-2xl">
            <h1 className="text-base font-bold text-white flex items-center space-x-2">
              <span className="h-3 w-3 rounded-full bg-red-500 animate-ping" />
              <span>HHH Platform Runtime Exception</span>
            </h1>
            <p className="text-xs text-platinum-300">{this.state.error?.message}</p>
            <pre className="p-3 bg-obsidian-950 rounded-xl overflow-x-auto text-[11px] text-red-300/80">
              {this.state.error?.stack}
            </pre>
            <button
              onClick={() => {
                localStorage.clear();
                window.location.reload();
              }}
              className="px-4 py-2 rounded-xl bg-white text-obsidian-950 font-bold text-xs"
            >
              Reset Session & Reload
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <ErrorBoundary>
    <AuthProvider>
      <App />
    </AuthProvider>
  </ErrorBoundary>,
);
