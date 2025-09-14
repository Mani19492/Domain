import React, { useState } from 'react';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Server, 
  Globe, 
  Eye,
  ChevronDown,
  ChevronUp,
  Download
} from 'lucide-react';
import { ReconData } from '../types/recon';
import { WorldMap } from './WorldMap';
import { generatePDF } from '../utils/pdfGenerator';

interface ReconResultsProps {
  data: ReconData;
}

interface SectionProps {
  title: string;
  icon: React.ReactNode;
  children: React.ReactNode;
  defaultOpen?: boolean;
}

const Section: React.FC<SectionProps> = ({ title, icon, children, defaultOpen = false }) => {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md mb-6">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full px-6 py-4 flex items-center justify-between text-left hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors rounded-lg"
      >
        <div className="flex items-center gap-3">
          {icon}
          <h3 className="text-xl font-semibold text-gray-900 dark:text-white">
            {title}
          </h3>
        </div>
        {isOpen ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
      </button>
      {isOpen && (
        <div className="px-6 pb-6 border-t border-gray-200 dark:border-gray-600">
          {children}
        </div>
      )}
    </div>
  );
};

export const ReconResults: React.FC<ReconResultsProps> = ({ data }) => {
  const handleDownloadPDF = () => {
    generatePDF(data);
  };

  return (
    <div className="max-w-4xl mx-auto">
      {/* Header with authenticity check */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6 mb-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
            Reconnaissance Report: {data.domain}
          </h2>
          <button
            onClick={handleDownloadPDF}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
          >
            <Download size={20} />
            Download PDF
          </button>
        </div>
        
        <div className={`flex items-center gap-3 p-4 rounded-lg ${
          data.isGenuine 
            ? 'bg-green-50 dark:bg-green-900/20 text-green-800 dark:text-green-200' 
            : 'bg-red-50 dark:bg-red-900/20 text-red-800 dark:text-red-200'
        }`}>
          {data.isGenuine ? (
            <CheckCircle className="text-green-600 dark:text-green-400" size={24} />
          ) : (
            <AlertTriangle className="text-red-600 dark:text-red-400" size={24} />
          )}
          <div>
            <div className="font-semibold">
              {data.isGenuine ? 'Domain Verified as Genuine' : 'Potential Security Risk Detected'}
            </div>
            <div className="text-sm mt-1">
              VirusTotal: {data.authenticity.vtResult.malicious} malicious, {data.authenticity.vtResult.suspicious} suspicious detections
            </div>
          </div>
        </div>
      </div>

      {/* World Map */}
      <WorldMap geolocation={data.geolocation} />

      {/* WHOIS Information */}
      <Section
        title="WHOIS Information"
        icon={<Globe className="text-blue-600 dark:text-blue-400" size={24} />}
        defaultOpen
      >
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
          <div>
            <span className="text-gray-500 dark:text-gray-400">Registrar:</span>
            <div className="font-medium text-gray-900 dark:text-white">
              {data.whois.registrar}
            </div>
          </div>
          <div>
            <span className="text-gray-500 dark:text-gray-400">Registrant:</span>
            <div className="font-medium text-gray-900 dark:text-white">
              {data.whois.registrant}
            </div>
          </div>
          <div>
            <span className="text-gray-500 dark:text-gray-400">Created:</span>
            <div className="font-medium text-gray-900 dark:text-white">
              {data.whois.created}
            </div>
          </div>
          <div>
            <span className="text-gray-500 dark:text-gray-400">Expires:</span>
            <div className="font-medium text-gray-900 dark:text-white">
              {data.whois.expires}
            </div>
          </div>
          <div className="md:col-span-2">
            <span className="text-gray-500 dark:text-gray-400">Name Servers:</span>
            <div className="font-medium text-gray-900 dark:text-white break-all">
              {data.whois.nameServers}
            </div>
          </div>
          <div className="md:col-span-2">
            <span className="text-gray-500 dark:text-gray-400">Status:</span>
            <div className="font-medium text-gray-900 dark:text-white">
              {data.whois.status}
            </div>
          </div>
        </div>
      </Section>

      {/* DNS Records */}
      <Section
        title="DNS Records"
        icon={<Server className="text-green-600 dark:text-green-400" size={24} />}
      >
        <div className="mt-4 space-y-2">
          {data.dns.map((record, index) => (
            <div key={index} className="flex items-start gap-4 p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
              <span className="font-mono text-sm bg-gray-200 dark:bg-gray-600 px-2 py-1 rounded text-gray-700 dark:text-gray-300">
                {record.type}
              </span>
              <span className="font-mono text-sm text-gray-900 dark:text-white break-all">
                {record.value}
              </span>
            </div>
          ))}
        </div>
      </Section>

      {/* SSL Certificate */}
      <Section
        title="SSL Certificate"
        icon={<Shield className="text-purple-600 dark:text-purple-400" size={24} />}
      >
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
          <div>
            <span className="text-gray-500 dark:text-gray-400">Issuer:</span>
            <div className="font-medium text-gray-900 dark:text-white">
              {data.ssl.issuer}
            </div>
          </div>
          <div>
            <span className="text-gray-500 dark:text-gray-400">Subject:</span>
            <div className="font-medium text-gray-900 dark:text-white">
              {data.ssl.subject}
            </div>
          </div>
          <div>
            <span className="text-gray-500 dark:text-gray-400">Expiry:</span>
            <div className="font-medium text-gray-900 dark:text-white">
              {data.ssl.expiry}
            </div>
          </div>
          <div>
            <span className="text-gray-500 dark:text-gray-400">Valid:</span>
            <div className={`font-medium ${data.ssl.valid ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>
              {data.ssl.valid ? 'Yes' : 'No'}
            </div>
          </div>
        </div>
      </Section>

      {/* Threat Intelligence */}
      <Section
        title="Threat Intelligence"
        icon={<Eye className="text-red-600 dark:text-red-400" size={24} />}
      >
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
          <div>
            <span className="text-gray-500 dark:text-gray-400">Reputation:</span>
            <div className="font-medium text-gray-900 dark:text-white">
              {data.threats.reputation}
            </div>
          </div>
          <div>
            <span className="text-gray-500 dark:text-gray-400">Last Analysis:</span>
            <div className="font-medium text-gray-900 dark:text-white">
              {data.threats.lastAnalysis}
            </div>
          </div>
          <div>
            <span className="text-gray-500 dark:text-gray-400">Malicious Detections:</span>
            <div className={`font-medium ${data.threats.malicious > 0 ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'}`}>
              {data.threats.malicious}
            </div>
          </div>
          <div>
            <span className="text-gray-500 dark:text-gray-400">Suspicious Detections:</span>
            <div className={`font-medium ${data.threats.suspicious > 0 ? 'text-yellow-600 dark:text-yellow-400' : 'text-green-600 dark:text-green-400'}`}>
              {data.threats.suspicious}
            </div>
          </div>
          {data.threats.categories.length > 0 && (
            <div className="md:col-span-2">
              <span className="text-gray-500 dark:text-gray-400">Categories:</span>
              <div className="flex flex-wrap gap-2 mt-2">
                {data.threats.categories.map((category, index) => (
                  <span
                    key={index}
                    className="px-3 py-1 bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded-full text-sm"
                  >
                    {category}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </Section>

      {/* Subdomains */}
      {data.subdomains.length > 0 && (
        <Section
          title={`Subdomains (${data.subdomains.length})`}
          icon={<Globe className="text-teal-600 dark:text-teal-400" size={24} />}
        >
          <div className="mt-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
            {data.subdomains.map((subdomain, index) => (
              <div
                key={index}
                className="p-2 bg-gray-50 dark:bg-gray-700 rounded text-sm font-mono text-gray-900 dark:text-white"
              >
                {subdomain}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Open Ports */}
      {data.openPorts.length > 0 && (
        <Section
          title="Open Ports"
          icon={<Server className="text-orange-600 dark:text-orange-400" size={24} />}
        >
          <div className="mt-4 flex flex-wrap gap-2">
            {data.openPorts.map((port, index) => (
              <span
                key={index}
                className="px-3 py-1 bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200 rounded-full text-sm font-mono"
              >
                {port}
              </span>
            ))}
          </div>
        </Section>
      )}

      {/* Technologies */}
      {data.technologies.length > 0 && (
        <Section
          title="Technologies"
          icon={<Server className="text-indigo-600 dark:text-indigo-400" size={24} />}
        >
          <div className="mt-4 space-y-2">
            {data.technologies.map((tech, index) => (
              <div
                key={index}
                className="p-3 bg-gray-50 dark:bg-gray-700 rounded-lg text-gray-900 dark:text-white"
              >
                {tech}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Security Headers */}
      <Section
        title="Security Headers"
        icon={<Shield className="text-cyan-600 dark:text-cyan-400" size={24} />}
      >
        <div className="mt-4 space-y-3">
          {Object.entries(data.securityHeaders).map(([header, value]) => (
            <div key={header} className="flex items-start gap-4">
              <span className="font-mono text-sm bg-gray-200 dark:bg-gray-600 px-2 py-1 rounded text-gray-700 dark:text-gray-300 min-w-0 flex-shrink-0">
                {header}
              </span>
              <span className={`font-mono text-sm break-all ${
                value === 'Not set' 
                  ? 'text-red-600 dark:text-red-400' 
                  : 'text-green-600 dark:text-green-400'
              }`}>
                {value}
              </span>
            </div>
          ))}
        </div>
      </Section>
    </div>
  );
};