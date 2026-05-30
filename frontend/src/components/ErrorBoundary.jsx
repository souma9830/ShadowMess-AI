import React, { Component } from 'react';

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("ErrorBoundary caught an error", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center w-full h-full bg-[#1a1a1a] border border-[#333] rounded-lg p-4">
          <div className="w-6 h-6 border-2 border-shadowRed border-t-transparent rounded-full animate-spin mb-2"></div>
          <div className="text-gray-400 text-sm font-mono">{this.props.componentName || 'Component'} Reconnecting...</div>
        </div>
      );
    }
    return this.props.children;
  }
}
