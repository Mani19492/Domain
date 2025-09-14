export interface WhoisData {
  registrar: string;
  registrant: string;
  created: string;
  expires: string;
  nameServers: string;
  status: string;
}

export interface DNSRecord {
  type: string;
  value: string;
}

export interface SSLData {
  issuer: string;
  subject: string;
  expiry: string;
  valid: boolean;
}

export interface ThreatData {
  reputation: number;
  lastAnalysis: string;
  categories: string[];
  malicious: number;
  suspicious: number;
}

export interface GeolocationData {
  country: string;
  city: string;
  isp: string;
  latitude: number;
  longitude: number;
}

export interface SecurityHeaders {
  [key: string]: string;
}

export interface ReconData {
  domain: string;
  ip: string;
  whois: WhoisData;
  dns: DNSRecord[];
  ssl: SSLData;
  threats: ThreatData;
  subdomains: string[];
  openPorts: string[];
  geolocation: GeolocationData;
  technologies: string[];
  securityHeaders: SecurityHeaders;
  isGenuine: boolean;
  authenticity: {
    vtResult: { malicious: number; suspicious: number };
    gsResult: { malicious: boolean; threatType: string } | null;
  };
}