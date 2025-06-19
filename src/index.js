const express = require('express');
const multer = require('multer');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const FormData = require('form-data');
const cors = require('cors');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Enable CORS
app.use(cors({
  origin: ['http://localhost:3001', 'http://127.0.0.1:3001'], // Allow your frontend origin
  methods: ['GET', 'POST', 'OPTIONS'], // Allow these HTTP methods
  allowedHeaders: ['Content-Type', 'Authorization'], // Allow these headers
  credentials: true // Allow cookies and credentials
}));

// Configure multer for file upload
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  }
});

const fileFilter = (req, file, cb) => {
  if (file.originalname.match(/\.(apk|zip|ipa|appx)$/)) {
    cb(null, true);
  } else {
    cb(new Error('Only APK, ZIP, IPA and APPX files are allowed!'), false);
  }
};

const upload = multer({ 
  storage: storage,
  fileFilter: fileFilter
});

// MobSF API configuration
const mobsfConfig = {
  baseURL: process.env.MOBSF_URL || 'http://localhost:8000',
  apiKey: process.env.MOBSF_API_KEY
};

// Upload endpoint
app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    console.log('File received:', {
      originalname: req.file.originalname,
      path: req.file.path,
      size: req.file.size
    });

    // Create form data
    const form = new FormData();
    const fileStream = fs.createReadStream(req.file.path);
    form.append('file', fileStream);

    console.log('Making upload request to:', `${mobsfConfig.baseURL}/api/v1/upload`);

    // Make the upload request
    const uploadResponse = await axios.post(
      `${mobsfConfig.baseURL}/api/v1/upload`,
      form,
      {
        headers: {
          'Authorization': mobsfConfig.apiKey,
          ...form.getHeaders()
        },
        maxContentLength: Infinity,
        maxBodyLength: Infinity
      }
    );

    console.log('MobSF Upload Response:', uploadResponse.data);

    if (!uploadResponse.data || !uploadResponse.data.hash) {
      throw new Error('Invalid response from MobSF upload');
    }

    // Prepare scan parameters
    const scanParams = new URLSearchParams();
    scanParams.append('scan_type', uploadResponse.data.scan_type);
    scanParams.append('file_name', uploadResponse.data.file_name);
    scanParams.append('hash', uploadResponse.data.hash);

    console.log('Making scan request with params:', Object.fromEntries(scanParams));

    // Make scan request with URL-encoded form data
    const scanResponse = await axios.post(
      `${mobsfConfig.baseURL}/api/v1/scan`,
      scanParams,
      {
        headers: {
          'Authorization': mobsfConfig.apiKey,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    console.log('MobSF Scan Response:', scanResponse.data);

    // Clean up the uploaded file
    fs.unlinkSync(req.file.path);

    res.json({
      message: 'File uploaded and scan started',
      scan_id: uploadResponse.data.hash,
      file_name: uploadResponse.data.file_name,
      scan_type: uploadResponse.data.scan_type,
      upload_response: uploadResponse.data,
      scan_response: scanResponse.data
    });

  } catch (error) {
    console.error('Upload error:', error.message);
    
    if (error.response) {
      console.error('Error response:', {
        status: error.response.status,
        statusText: error.response.statusText,
        data: error.response.data,
        headers: error.response.headers
      });
      console.error('Failed request details:', {
        url: error.config.url,
        method: error.config.method,
        data: error.config.data,
        headers: {
          ...error.config.headers,
          'Authorization': 'REDACTED'
        }
      });
    } else {
      console.error('Full error:', error);
    }
    
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    
    res.status(500).json({ 
      error: 'Error uploading file to MobSF',
      details: error.response?.data || error.message,
      full_error: error.toString()
    });
  }
});

// Helper function to extract critical issues
function extractCriticalIssues(report) {
  const criticalIssues = [];
  
  // Add permission hotspots
  if (report.permissions?.dangerous?.length > 0) {
    criticalIssues.push({
      category: 'permissions',
      title: `Found ${report.permissions.dangerous.length} critical permission(s)`,
      description: formatPermissionsDescription(report.permissions.dangerous),
      severity: 'high',
      permissions: report.permissions.dangerous.map(perm => ({
        name: perm.name || perm,
        status: perm.status || 'dangerous',
        description: perm.description || '',
        info: perm.info || ''
      }))
    });
  }

  // Categories to check for critical issues
  const categories = [
    'android_apis',
    'code_analysis',
    'file_analysis',
    'manifest_analysis',
    'network_security',
    'binary_analysis'
  ];

  categories.forEach(category => {
    if (report[category]) {
      Object.entries(report[category]).forEach(([key, finding]) => {
        if (finding.severity === 'high' || (finding.cvss && finding.cvss >= 7.0)) {
          criticalIssues.push({
            category,
            title: key,
            description: finding.description,
            severity: finding.severity,
            cvss: finding.cvss || null,
            cwe: finding.cwe || null,
            owasp: finding.owasp || null,
            masvs: finding.masvs || null,
            reference: finding.ref || null,
            files: finding.files || null
          });
        }
      });
    }
  });

  return criticalIssues;
}

// Helper function to format permissions description
function formatPermissionsDescription(permissions) {
  const descriptions = permissions.map(perm => {
    const permName = typeof perm === 'string' ? perm : perm.name;
    const permDesc = typeof perm === 'string' ? '' : perm.description || '';
    const permInfo = typeof perm === 'string' ? '' : perm.info || '';
    
    return `${permName} (dangerous): ${permDesc}${permInfo ? ` - ${permInfo}` : ''}`;
  });

  return `Ensure that these permissions are required by the application.\n\n${descriptions.join('\n\n')}`;
}

// Helper function to extract security hotspots
function extractSecurityHotspots(report) {
  return {
    // Dangerous permissions that could be exploited
    permissions: {
      dangerous: formatPermissionsList(report.permissions?.dangerous),
      critical: formatPermissionsList(report.permissions?.critical),
      count: {
        dangerous: report.permissions?.dangerous?.length || 0,
        critical: report.permissions?.critical?.length || 0
      }
    },
    
    // Exposed components that might be vulnerable
    exposedComponents: extractExposedComponents(report),
    
    // Network security configuration issues
    networkSecurity: extractNetworkSecurityIssues(report),
    
    // Certificate issues
    certificates: extractCertificateIssues(report),
    
    // File-based vulnerabilities
    files: extractFileBasedIssues(report)
  };
}

// Helper function to format permissions list
function formatPermissionsList(permissions) {
  if (!permissions) return [];
  
  return permissions.map(perm => {
    if (typeof perm === 'string') {
      return {
        name: perm,
        status: 'dangerous',
        description: '',
        info: ''
      };
    }
    return {
      name: perm.name,
      status: perm.status || 'dangerous',
      description: perm.description || '',
      info: perm.info || ''
    };
  });
}

// Helper function to extract exposed components
function extractExposedComponents(report) {
  const exposedComponents = [];

  // Check for exported components that might be vulnerable
  ['activities', 'services', 'receivers', 'providers'].forEach(componentType => {
    if (report[componentType]) {
      report[componentType].forEach(component => {
        if (component.exported === true) {
          exposedComponents.push({
            type: componentType,
            name: component.name,
            permission: component.permission || null,
            intentFilters: component.intent_filters || [],
            dataSchemes: component.data_schemes || []
          });
        }
      });
    }
  });

  return exposedComponents;
}

// Helper function to extract network security issues
function extractNetworkSecurityIssues(report) {
  const networkIssues = [];

  // Check network security config
  if (report.network_security) {
    if (report.network_security.clear_text_traffic === true) {
      networkIssues.push({
        type: 'cleartext_traffic',
        description: 'Clear text traffic is allowed'
      });
    }
  }

  // Check for insecure URLs
  if (report.urls && Array.isArray(report.urls)) {
    report.urls.forEach(urlEntry => {
      // Handle both string URLs and URL objects
      const url = typeof urlEntry === 'string' ? urlEntry : urlEntry.url || urlEntry.URI || '';
      
      if (url && typeof url === 'string' && url.toLowerCase().startsWith('http://')) {
        networkIssues.push({
          type: 'insecure_url',
          url: url,
          description: 'Insecure HTTP URL found',
          context: typeof urlEntry === 'object' ? urlEntry : null
        });
      }
    });
  }

  return networkIssues;
}

// Helper function to extract certificate issues
function extractCertificateIssues(report) {
  const certIssues = [];

  if (report.certificate_analysis) {
    Object.entries(report.certificate_analysis).forEach(([key, finding]) => {
      if (finding.severity === 'high' || finding.severity === 'warning') {
        certIssues.push({
          issue: key,
          description: finding.description,
          severity: finding.severity
        });
      }
    });
  }

  return certIssues;
}

// Helper function to extract file-based issues
function extractFileBasedIssues(report) {
  const fileIssues = [];

  if (report.file_analysis) {
    Object.entries(report.file_analysis).forEach(([key, finding]) => {
      if (finding.severity === 'high' || finding.severity === 'warning') {
        fileIssues.push({
          type: key,
          description: finding.description,
          severity: finding.severity,
          files: finding.files || []
        });
      }
    });
  }

  return fileIssues;
}

// Get report endpoint
app.get('/api/report/:scanId', async (req, res) => {
  try {
    const { scanId } = req.params;

    // Create parameters
    const params = new URLSearchParams();
    params.append('hash', scanId);

    const reportResponse = await axios.post(
      `${mobsfConfig.baseURL}/api/v1/report_json`,
      params,
      {
        headers: {
          'Authorization': mobsfConfig.apiKey,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const report = reportResponse.data;

    // Extract critical issues and hotspots
    const findings = {
      criticalIssues: extractCriticalIssues(report),
      hotspots: extractSecurityHotspots(report),
      malwareFindings: report.virus_total || {},
      appInfo: {
        appName: report.app_name,
        packageName: report.package_name,
        version: report.version_name,
        sha256: report.sha256,
        md5: report.md5
      }
    };

    // Add summary
    findings.summary = {
      totalCriticalIssues: findings.criticalIssues.length,
      totalDangerousPermissions: findings.hotspots.permissions.count.dangerous,
      totalCriticalPermissions: findings.hotspots.permissions.count.critical,
      totalExposedComponents: findings.hotspots.exposedComponents.length,
      totalNetworkIssues: findings.hotspots.networkSecurity.length,
      totalCertificateIssues: findings.hotspots.certificates.length,
      totalFileIssues: findings.hotspots.files.length
    };

    res.json(findings);

  } catch (error) {
    console.error('Report error:', error.message);
    if (error.response) {
      console.error('Error response:', {
        status: error.response.status,
        data: error.response.data,
        headers: error.response.headers
      });
    }
    
    res.status(500).json({ 
      error: 'Error fetching report from MobSF',
      details: error.response?.data || error.message
    });
  }
});

app.use((err, req, res, next) => {
  console.error('Global error:', err.message);
  res.status(500).json({ 
    error: 'Something went wrong!', 
    details: err.message 
  });
});

if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
}); 