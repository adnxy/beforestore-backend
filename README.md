# MobSF API Integration

This is a Node.js API that integrates with MobSF (Mobile Security Framework) for analyzing mobile applications.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Create a `.env` file in the root directory with the following content:
```
MOBSF_API_KEY=your_api_key_here
MOBSF_URL=http://localhost:8000
```

3. Start the server:
```bash
npm run dev
```

## API Endpoints

### Upload File
- **URL**: `/api/upload`
- **Method**: `POST`
- **Content-Type**: `multipart/form-data`
- **Parameter**: `file` (APK or IPA file)
- **Response**: Returns scan ID for the uploaded file

Example using curl:
```bash
curl -X POST -F "file=@/path/to/your/app.apk" http://localhost:3000/api/upload
```

### Get Report
- **URL**: `/api/report/:scanId`
- **Method**: `GET`
- **Response**: Returns the detailed security analysis report

Example using curl:
```bash
curl http://localhost:3000/api/report/your_scan_id_here
```

## Notes
- Make sure MobSF is running and accessible at the URL specified in your `.env` file
- The API key can be found in your MobSF installation
- Uploaded files are temporarily stored in the `uploads` directory 