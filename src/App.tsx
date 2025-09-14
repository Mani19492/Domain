import React, { useState } from 'react';
import { SearchForm } from './components/SearchForm';
import { LoadingSpinner } from './components/LoadingSpinner';
import { ReconResults } from './components/ReconResults';
import { ThemeToggle } from './components/ThemeToggle';
import { useTheme } from './hooks/useTheme';
import { reconService } from './services/reconService';
import { ReconData } from './types/recon';

function App() {
  useTheme(); // Initialize theme
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<ReconData | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (domain: string) => {
    setLoading(true);
    setError(null);
    setResults(null);

    try {
      const data = await reconService.getReconData(domain);
      setResults(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred during reconnaissance');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 transition-colors">
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex justify-between items-center">
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-semibold text-gray-900 dark:text-white">
                Domain Reconnaissance Tool
              </h1>
            </div>
            <ThemeToggle />
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <SearchForm onSubmit={handleScan} loading={loading} />

        {error && (
          <div className="max-w-4xl mx-auto mb-8">
            <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
              <div className="text-red-800 dark:text-red-200 font-medium">
                Error: {error}
              </div>
            </div>
          </div>
        )}

        {loading && <LoadingSpinner domain="Loading..." />}

        {results && <ReconResults data={results} />}
      </main>

      {/* Footer */}
      <footer className="bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 mt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-center text-gray-600 dark:text-gray-400">
            <p>Domain Reconnaissance Tool - Professional domain analysis and threat intelligence</p>
            <p className="mt-2 text-sm">
              Built with security and privacy in mind. All scans are performed in real-time.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;