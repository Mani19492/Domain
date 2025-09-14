import React, { useState } from 'react';
import { Search, Shield } from 'lucide-react';

interface SearchFormProps {
  onSubmit: (domain: string) => void;
  loading: boolean;
}

export const SearchForm: React.FC<SearchFormProps> = ({ onSubmit, loading }) => {
  const [domain, setDomain] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (domain.trim()) {
      onSubmit(domain.trim());
    }
  };

  return (
    <div className="max-w-2xl mx-auto mb-8">
      <div className="text-center mb-8">
        <div className="flex items-center justify-center gap-3 mb-4">
          <Shield className="text-blue-600 dark:text-blue-400" size={32} />
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            Domain Reconnaissance
          </h1>
        </div>
        <p className="text-gray-600 dark:text-gray-300">
          Comprehensive domain analysis with threat intelligence and security assessment
        </p>
      </div>
      
      <form onSubmit={handleSubmit} className="flex gap-3">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={20} />
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="Enter domain name (e.g., example.com)"
            className="w-full pl-10 pr-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-800 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500"
            disabled={loading}
          />
        </div>
        <button
          type="submit"
          disabled={loading || !domain.trim()}
          className="px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-lg font-medium transition-colors flex items-center gap-2"
        >
          {loading ? (
            <>
              <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
              Scanning...
            </>
          ) : (
            'Scan Domain'
          )}
        </button>
      </form>
    </div>
  );
};