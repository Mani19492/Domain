import React from 'react';

interface LoadingSpinnerProps {
  domain: string;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({ domain }) => {
  return (
    <div className="max-w-4xl mx-auto">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-8 text-center">
        <div className="w-12 h-12 border-4 border-blue-200 border-t-blue-600 rounded-full animate-spin mx-auto mb-4"></div>
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
          Analyzing {domain}
        </h3>
        <p className="text-gray-600 dark:text-gray-300">
          Please wait while we gather reconnaissance data. This may take 30-60 seconds...
        </p>
        <div className="mt-6 space-y-2">
          <div className="text-sm text-gray-500 dark:text-gray-400">
            • Checking domain authenticity
          </div>
          <div className="text-sm text-gray-500 dark:text-gray-400">
            • Gathering WHOIS information
          </div>
          <div className="text-sm text-gray-500 dark:text-gray-400">
            • Analyzing DNS records
          </div>
          <div className="text-sm text-gray-500 dark:text-gray-400">
            • Scanning for threats
          </div>
        </div>
      </div>
    </div>
  );
};