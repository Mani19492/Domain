import { ReconData, WhoisData, DNSRecord, SSLData, ThreatData, GeolocationData } from '../types/recon';

const API_KEYS = {
  VIRUSTOTAL: import.meta.env.VITE_VIRUSTOTAL_API_KEY,
  WHOISXML: import.meta.env.VITE_WHOISXMLAPI_KEY,
  GOOGLE_SAFE_BROWSING: import.meta.env.VITE_GOOGLE_SAFE_BROWSING_API_KEY,
};

class ReconService {
  private cache = new Map<string, any>();

  async getReconData(domain: string): Promise<ReconData> {
    const cacheKey = `recon-${domain}`;
    if (this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey);
    }

    try {
      const [
        ip,
        whois,
        dns,
        ssl,
        threats,
        subdomains,
        openPorts,
        geolocation,
        technologies,
        securityHeaders,
        authenticity
      ] = await Promise.allSettled([
        this.getIP(domain),
        this.getWhoisData(domain),
        this.getDNSRecords(domain),
        this.getSSLData(domain),
        this.getThreatData(domain),
        this.getSubdomains(domain),
        this.getOpenPorts(domain),
        this.getGeolocation(domain),
        this.getTechnologies(domain),
        this.getSecurityHeaders(domain),
        this.checkAuthenticity(domain)
      ]);

      const reconData: ReconData = {
        domain,
        ip: this.getSettledValue(ip, ''),
        whois: this.getSettledValue(whois, this.getDefaultWhois()),
        dns: this.getSettledValue(dns, []),
        ssl: this.getSettledValue(ssl, this.getDefaultSSL()),
        threats: this.getSettledValue(threats, this.getDefaultThreats()),
        subdomains: this.getSettledValue(subdomains, []),
        openPorts: this.getSettledValue(openPorts, []),
        geolocation: this.getSettledValue(geolocation, this.getDefaultGeolocation()),
        technologies: this.getSettledValue(technologies, []),
        securityHeaders: this.getSettledValue(securityHeaders, {}),
        isGenuine: this.getSettledValue(authenticity, { isGenuine: true }).isGenuine,
        authenticity: this.getSettledValue(authenticity, { vtResult: { malicious: 0, suspicious: 0 }, gsResult: null })
      };

      this.cache.set(cacheKey, reconData);
      return reconData;
    } catch (error) {
      console.error('Error getting recon data:', error);
      throw error;
    }
  }

  private getSettledValue<T>(result: PromiseSettledResult<T>, defaultValue: T): T {
    return result.status === 'fulfilled' ? result.value : defaultValue;
  }

  private async getIP(domain: string): Promise<string> {
    try {
      const response = await fetch(`https://dns.google/resolve?name=${domain}&type=A`);
      const data = await response.json();
      return data.Answer?.[0]?.data || '';
    } catch (error) {
      console.error('IP resolution failed:', error);
      return '';
    }
  }

  private async getWhoisData(domain: string): Promise<WhoisData> {
    if (!API_KEYS.WHOISXML) {
      throw new Error('WHOISXML API key not configured');
    }

    try {
      const response = await fetch(
        `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${API_KEYS.WHOISXML}&domainName=${domain}&outputFormat=JSON`
      );
      const data = await response.json();
      const whoisData = data.WhoisRecord || {};

      return {
        registrar: whoisData.registrarName || 'N/A',
        registrant: whoisData.registrant?.name || 'Privacy Protected',
        created: whoisData.createdDate || 'N/A',
        expires: whoisData.expiresDate || 'N/A',
        nameServers: whoisData.nameServers?.hostNames?.join(', ') || 'N/A',
        status: whoisData.status?.join(', ') || 'N/A'
      };
    } catch (error) {
      console.error('WHOIS lookup failed:', error);
      return this.getDefaultWhois();
    }
  }

  private async getDNSRecords(domain: string): Promise<DNSRecord[]> {
    const records: DNSRecord[] = [];
    const types = ['A', 'AAAA', 'MX', 'NS', 'TXT'];

    for (const type of types) {
      try {
        const response = await fetch(`https://dns.google/resolve?name=${domain}&type=${type}`);
        const data = await response.json();
        if (data.Answer) {
          data.Answer.forEach((answer: any) => {
            records.push({ type, value: answer.data });
          });
        }
      } catch (error) {
        records.push({ type, value: 'No records found' });
      }
    }

    return records;
  }

  private async getSSLData(domain: string): Promise<SSLData> {
    try {
      // This would typically require a backend service for SSL certificate inspection
      // For now, we'll return mock data or make a request to a public API
      return {
        issuer: 'Unknown',
        subject: domain,
        expiry: 'Unknown',
        valid: true
      };
    } catch (error) {
      return this.getDefaultSSL();
    }
  }

  private async getThreatData(domain: string): Promise<ThreatData> {
    if (!API_KEYS.VIRUSTOTAL) {
      throw new Error('VirusTotal API key not configured');
    }

    try {
      const response = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, {
        headers: { 'x-apikey': API_KEYS.VIRUSTOTAL }
      });
      const data = await response.json();
      const attributes = data.data.attributes;

      return {
        reputation: attributes.reputation || 0,
        lastAnalysis: attributes.last_analysis_date || 'N/A',
        categories: Object.values(attributes.categories || {}),
        malicious: attributes.last_analysis_stats?.malicious || 0,
        suspicious: attributes.last_analysis_stats?.suspicious || 0
      };
    } catch (error) {
      console.error('Threat data lookup failed:', error);
      return this.getDefaultThreats();
    }
  }

  private async getSubdomains(domain: string): Promise<string[]> {
    try {
      const response = await fetch(`https://crt.sh/?q=%.${domain}&output=json`);
      const data = await response.json();
      const subdomains = new Set<string>();
      data.forEach((entry: any) => {
        if (entry.name_value) {
          subdomains.add(entry.name_value.trim());
        }
      });
      return Array.from(subdomains).slice(0, 20); // Limit to 20 subdomains
    } catch (error) {
      console.error('Subdomain lookup failed:', error);
      return [];
    }
  }

  private async getOpenPorts(domain: string): Promise<string[]> {
    // This would typically require a backend service for port scanning
    // For demo purposes, we'll return common open ports
    return ['80', '443'];
  }

  private async getGeolocation(domain: string): Promise<GeolocationData> {
    try {
      const ip = await this.getIP(domain);
      if (!ip) throw new Error('No IP found');

      const response = await fetch(`http://ip-api.com/json/${ip}`);
      const data = await response.json();

      return {
        country: data.country || 'Unknown',
        city: data.city || 'Unknown',
        isp: data.isp || 'Unknown',
        latitude: data.lat || 0,
        longitude: data.lon || 0
      };
    } catch (error) {
      console.error('Geolocation lookup failed:', error);
      return this.getDefaultGeolocation();
    }
  }

  private async getTechnologies(domain: string): Promise<string[]> {
    try {
      const response = await fetch(`https://${domain}`, { mode: 'cors' });
      const headers = response.headers;
      const technologies: string[] = [];

      if (headers.get('server')) {
        technologies.push(`Server: ${headers.get('server')}`);
      }
      if (headers.get('x-powered-by')) {
        technologies.push(`Powered By: ${headers.get('x-powered-by')}`);
      }

      return technologies;
    } catch (error) {
      return [];
    }
  }

  private async getSecurityHeaders(domain: string): Promise<{ [key: string]: string }> {
    try {
      const response = await fetch(`https://${domain}`, { mode: 'cors' });
      const securityHeaders = [
        'content-security-policy',
        'x-frame-options',
        'x-content-type-options',
        'strict-transport-security',
        'referrer-policy'
      ];

      const headers: { [key: string]: string } = {};
      securityHeaders.forEach(header => {
        headers[header] = response.headers.get(header) || 'Not set';
      });

      return headers;
    } catch (error) {
      return {};
    }
  }

  private async checkAuthenticity(domain: string): Promise<any> {
    try {
      const vtResult = await this.checkVirusTotal(domain);
      const gsResult = await this.checkGoogleSafeBrowsing(domain);
      
      const isGenuine = vtResult.malicious === 0 && vtResult.suspicious === 0 && 
                       (!gsResult || !gsResult.malicious);

      return {
        isGenuine,
        vtResult,
        gsResult
      };
    } catch (error) {
      return {
        isGenuine: true,
        vtResult: { malicious: 0, suspicious: 0 },
        gsResult: null
      };
    }
  }

  private async checkVirusTotal(domain: string): Promise<{ malicious: number; suspicious: number }> {
    if (!API_KEYS.VIRUSTOTAL) {
      return { malicious: 0, suspicious: 0 };
    }

    try {
      const url = `https://${domain}`;
      const urlId = btoa(url).replace(/=/g, '');
      const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        headers: { 'x-apikey': API_KEYS.VIRUSTOTAL }
      });
      
      if (response.status === 200) {
        const data = await response.json();
        const stats = data.data.attributes.last_analysis_stats;
        return {
          malicious: stats.malicious || 0,
          suspicious: stats.suspicious || 0
        };
      }
    } catch (error) {
      console.error('VirusTotal check failed:', error);
    }

    return { malicious: 0, suspicious: 0 };
  }

  private async checkGoogleSafeBrowsing(domain: string): Promise<{ malicious: boolean; threatType: string } | null> {
    if (!API_KEYS.GOOGLE_SAFE_BROWSING) {
      return null;
    }

    try {
      const response = await fetch(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEYS.GOOGLE_SAFE_BROWSING}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client: { clientId: 'domain-recon-web', clientVersion: '1.0' },
            threatInfo: {
              threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
              platformTypes: ['ANY_PLATFORM'],
              threatEntryTypes: ['URL'],
              threatEntries: [{ url: `https://${domain}` }]
            }
          })
        }
      );

      const data = await response.json();
      const matches = data.matches || [];
      
      return {
        malicious: matches.length > 0,
        threatType: matches[0]?.threatType || 'Safe'
      };
    } catch (error) {
      console.error('Google Safe Browsing check failed:', error);
      return null;
    }
  }

  private getDefaultWhois(): WhoisData {
    return {
      registrar: 'N/A',
      registrant: 'N/A',
      created: 'N/A',
      expires: 'N/A',
      nameServers: 'N/A',
      status: 'N/A'
    };
  }

  private getDefaultSSL(): SSLData {
    return {
      issuer: 'N/A',
      subject: 'N/A',
      expiry: 'N/A',
      valid: false
    };
  }

  private getDefaultThreats(): ThreatData {
    return {
      reputation: 0,
      lastAnalysis: 'N/A',
      categories: [],
      malicious: 0,
      suspicious: 0
    };
  }

  private getDefaultGeolocation(): GeolocationData {
    return {
      country: 'Unknown',
      city: 'Unknown',
      isp: 'Unknown',
      latitude: 0,
      longitude: 0
    };
  }
}

export const reconService = new ReconService();