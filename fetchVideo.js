const fs = require('fs');
const crypto = require('crypto');
const { URL } = require('url');
const sjcl = require('sjcl');
const pako = require('pako');
const puppeteer = require('puppeteer');

// Configuration
// NOTE: If you get "Signature verification failed" error, your authorization token has expired.
// Get a fresh token from your browser's Network tab when making the API request.
const API_URL = "https://harkiratapi.classx.co.in/get/fetchVideoDetailsById?course_id=14&video_id=3645&ytflag=0&folder_wise_course=1&linked_course_id=&lc_app_api_url=";
const HEADERS = {
  "accept": "*/*",
  "auth-key": "appxapi",
  "authorization": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjI0NzkwIiwiZW1haWwiOiJiaGFyYXRoc3VidTIwMDJAZ21haWwuY29tIiwidGltZXN0YW1wIjoxNzYwMjk0NTI4LCJ0ZW5hbnRUeXBlIjoidXNlciIsInRlbmFudE5hbWUiOiJoYXJraXJhdF9kYiIsInRlbmFudElkIjoiIiwiZGlzcG9zYWJsZSI6ZmFsc2V9.1C2sxSky2IfibmG4DmEyKt4bC40Amkm0CoOjLinHo3k",
  "client-service": "Appx",
  "device-type": "origin",
  "user-id": "24790",
  "origin": "https://harkirat.classx.co.in",
  "referer": "https://harkirat.classx.co.in/"
};

// Fetch video details from API (same style as fetch.js)
async function fetchVideoDetails() {
  console.log('\n========== STEP 1: Fetching Video Details ==========');
  console.log(`[API] URL: ${API_URL}`);
  console.log(`[API] Headers:`, JSON.stringify(HEADERS, null, 2));
  
  try {
    console.log(`[FETCH] Making GET request to: ${API_URL}`);
    const res = await fetch(API_URL, {
      method: "GET",
      headers: HEADERS
    });

    console.log(`[FETCH] Response status: ${res.status}`);
    
    if (res.status !== 200) {
      const errorText = await res.text();
      console.error(`[API] Error response body:`, errorText.substring(0, 1000));
      
      if (errorText.includes('Signature verification failed')) {
        console.error('\n[API] ⚠️  TOKEN ERROR: Your authorization token has expired or is invalid.');
        console.error('[API] Please get a fresh token from your browser:');
        console.error('[API] 1. Open browser DevTools (F12)');
        console.error('[API] 2. Go to Network tab');
        console.error('[API] 3. Make the API request in browser');
        console.error('[API] 4. Copy the "authorization" header value');
        console.error('[API] 5. Update the HEADERS.authorization in fetchVideo.js\n');
      }
      
      throw new Error(`API returned status ${res.status}: ${errorText.substring(0, 200)}`);
    }
    
    const data = await res.json();
    console.log('[API] Response received successfully');
    console.log('[API] Full response:', JSON.stringify(data, null, 2));
    
    if (data.data && data.data.video_player_token) {
      console.log(`[API] ✅ Found video_player_token: ${data.data.video_player_token}`);
    } else {
      console.warn('[API] ⚠️  video_player_token not found in response');
    }
    
    return data;
  } catch (err) {
    console.error("[API] Error fetching video details:", err);
    throw err;
  }
}

// Extract token and player URL from video details
function extractVideoInfo(videoData) {
  console.log('\n========== STEP 2: Extracting Video Info ==========');
  
  let token = null;
  let playerUrl = null;
  
  // Extract from data object
  if (videoData.data) {
    const data = videoData.data;
    
    // Extract video_player_token
    if (data.video_player_token) {
      token = data.video_player_token;
      console.log(`[EXTRACT] Found video_player_token: ${token}`);
    }
    
    // Build player URL with token
    if (token && data.video_player_url) {
      playerUrl = data.video_player_url + token;
      console.log(`[EXTRACT] Player URL: ${playerUrl}`);
    } else if (token) {
      // Fallback: construct URL manually
      playerUrl = `https://appx-play.classx.co.in/combined-img-player?isMobile=true&token=${token}`;
      console.log(`[EXTRACT] Constructed player URL: ${playerUrl}`);
    }
    
  }
  
  console.log(`[EXTRACT] Final token: ${token ? token : 'NOT FOUND'}`);
  console.log(`[EXTRACT] Final player URL: ${playerUrl || 'NOT FOUND'}`);
  
  if (!token) {
    throw new Error('video_player_token not found in API response');
  }
  
  if (!playerUrl) {
    throw new Error('Could not construct player URL');
  }
  
  return { token, playerUrl };
}

// Derive decryption key from timestamp and token (hls_tts_bypass method)
// This matches the Python get_data_enc_key function:
// def get_data_enc_key(time_val,token):
//     n = time_val[-4:]  # Last 4 characters of time_val
//     r = int(n[0])  # First character of n as an integer
//     i = int(n[1:3])  # Next two characters of n as an integer
//     o = int(n[3])  # Last character of n as an integer
//     a = time_val + token[r:i]
//     s = hashlib.sha256()
//     s.update(a.encode('utf-8'))
//     c = s.digest()
//     if o == 6:
//         sign = c[:16]  # First 16 bytes
//     elif o == 7:
//         sign = c[:24]  # First 24 bytes
//     else:
//         sign = c  # Entire hash
//     key = base64.b64encode(sign).decode('utf-8')
//     return key
function getDataEncKey(timeVal, token) {
  console.log(`[KEY_DERIVE] Deriving key from timestamp: ${timeVal}, token: ${token.substring(0, 20)}...`);
  
  // Extract parts of the timestamp
  const n = timeVal.slice(-4);  // Last 4 characters
  const r = parseInt(n[0]);      // First character as integer
  const i = parseInt(n.slice(1, 3));  // Next two characters as integer
  const o = parseInt(n[3]);      // Last character as integer
  
  console.log(`[KEY_DERIVE] Extracted: r=${r}, i=${i}, o=${o}`);
  
  // Create the string: timestamp + substring of token
  const a = timeVal + token.substring(r, i);
  console.log(`[KEY_DERIVE] Combined string: ${timeVal} + token[${r}:${i}]`);
  console.log(`[KEY_DERIVE] Combined string length: ${a.length}`);
  
  // Create SHA-256 hash
  const hash = crypto.createHash('sha256');
  hash.update(a, 'utf8');
  const c = hash.digest();  // This is a Buffer
  
  // Determine key length based on last digit (o)
  let sign;
  if (o === 6) {
    sign = c.slice(0, 16);  // First 16 bytes (AES-128)
    console.log(`[KEY_DERIVE] Using 16-byte key (AES-128)`);
  } else if (o === 7) {
    sign = c.slice(0, 24);  // First 24 bytes (AES-192)
    console.log(`[KEY_DERIVE] Using 24-byte key (AES-192)`);
  } else {
    sign = c;  // Entire hash (32 bytes for AES-256)
    console.log(`[KEY_DERIVE] Using 32-byte key (AES-256)`);
  }
  
  // Convert to base64 string (matching Python: base64.b64encode(sign).decode('utf-8'))
  const keyBase64 = sign.toString('base64');
  console.log(`[KEY_DERIVE] ✅ Derived key (base64): ${keyBase64.substring(0, 30)}...`);
  
  // Return both Buffer and base64 string for flexibility
  // Note: Python version returns base64 string, but we can use Buffer directly in decryptData
  return { key: sign, keyBase64: keyBase64 };
}

// Decrypt data using AES-CBC (for kstr and jstr)
// This matches the Python decrypt_data function:
// def decrypt_data(data,key,ivb):
//     i = b64decode(key)  # Key got from get_data_enc_key()
//     o = b64decode(ivb)  # Initialization Vector (IV)
//     a = b64decode(data)  # Encrypted data
//     cipher = AES.new(i, AES.MODE_CBC, o)
//     l = cipher.decrypt(a)
//     dec = l.decode('utf-8')
//     return dec
function decryptData(encryptedData, key, ivb) {
  try {
    // Key: Can be Buffer (from getDataEncKey) or base64 string
    // If it's a Buffer, we need to encode it to base64 first (to match Python behavior),
    // OR we can use it directly. Let's use it directly if it's a Buffer.
    let keyBuffer;
    if (Buffer.isBuffer(key)) {
      keyBuffer = key;
    } else if (typeof key === 'string') {
      // If it's a string, assume it's base64
      keyBuffer = Buffer.from(key, 'base64');
    } else {
      // If it's an object with key/keyBase64, use the Buffer
      keyBuffer = key.key || Buffer.from(key.keyBase64, 'base64');
    }
    
    // IV: Must be base64 string (from JSON)
    const ivBuffer = Buffer.from(ivb, 'base64');
    
    // Data: Must be base64 string (jstr or kstr from JSON)
    const dataBuffer = Buffer.from(encryptedData, 'base64');
    
    console.log(`[DECRYPT_DATA] Key length: ${keyBuffer.length} bytes, IV length: ${ivBuffer.length} bytes, Data length: ${dataBuffer.length} bytes`);
    
    // Ensure key and IV are exactly 16 bytes for AES-128-CBC
    const aesKey = keyBuffer.length >= 16 ? keyBuffer.slice(0, 16) : Buffer.concat([keyBuffer, Buffer.alloc(16 - keyBuffer.length, 0)]);
    const aesIV = ivBuffer.length >= 16 ? ivBuffer.slice(0, 16) : Buffer.concat([Buffer.alloc(16 - ivBuffer.length, 0), ivBuffer]);
    
    // Create AES cipher in CBC mode
    const decipher = crypto.createDecipheriv('aes-128-cbc', aesKey, aesIV);
    decipher.setAutoPadding(true);
    
    // Decrypt
    const decrypted = Buffer.concat([
      decipher.update(dataBuffer),
      decipher.final()
    ]);
    
    // Convert decrypted data to UTF-8 string (matching Python: l.decode('utf-8'))
    const decryptedStr = decrypted.toString('utf8');
    console.log(`[DECRYPT_DATA] ✅ Decrypted ${decryptedStr.length} characters`);
    
    return decryptedStr;
  } catch (err) {
    console.error('[DECRYPT_DATA] Error:', err);
    throw err;
  }
}

// Extract kstr, jstr, datetime, ivb6 from HTML JSON
function extractEncryptedDataFromHTML(html) {
  console.log('\n========== STEP 3: Extracting Encrypted Data from HTML ==========');
  
  // Look for JSON data in script tags or __NEXT_DATA__ or __next_f
  const jsonPatterns = [
    /<script[^>]*id="__NEXT_DATA__"[^>]*>(.*?)<\/script>/is,
    /window\.__NEXT_DATA__\s*=\s*({.*?});/is,
    /self\.__next_f\.push\(\[.*?,\s*"([^"]+)"\]\)/gi,  // Next.js Flight data
    /__next_f\.push\(\[.*?,\s*"([^"]+)"\]\)/gi,
    /"kstr"\s*:\s*"([^"]+)"/gi,
    /"jstr"\s*:\s*"([^"]+)"/gi,
    /"datetime"\s*:\s*"([^"]+)"/gi,
    /"ivb6"\s*:\s*"([^"]+)"/gi
  ];
  
  let jsonData = null;
  let kstr = null;
  let jstr = null;
  let datetime = null;
  let ivb6 = null;
  let token = null;
  
  // First, try to extract from __next_f.push() calls (Next.js Flight data)
  console.log(`[EXTRACT] Searching for __next_f.push() data...`);
  
  // Pattern to match __next_f.push([1, "..."]) or self.__next_f.push([1, "..."])
  // The string might contain escaped quotes, so we need to handle that
  const nextFPushPattern = /(?:self\.)?__next_f\.push\(\[[^,]+,\s*"((?:[^"\\]|\\.)+)"\]\)/gi;
  let match;
  const flightDataStrings = [];
  
  while ((match = nextFPushPattern.exec(html)) !== null) {
    // Unescape the string (handle \\ and \")
    let flightData = match[1].replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    flightDataStrings.push(flightData);
    
    // Check if this contains our keywords
    if (flightData.includes('"kstr"') || flightData.includes('"jstr"') || flightData.includes('"datetime"') || flightData.includes('"ivb6"')) {
      console.log(`[EXTRACT] Found __next_f data with keywords (length: ${flightData.length})`);
      
      // Extract datetime and ivb6 directly (these are usually in the same push)
      if (!datetime) {
        const datetimeMatch = flightData.match(/"datetime"\s*:\s*"([^"]+)"/);
        if (datetimeMatch && datetimeMatch[1]) {
          datetime = datetimeMatch[1];
          console.log(`[EXTRACT] Found datetime in __next_f: ${datetime}`);
        }
      }
      
      if (!ivb6) {
        const ivb6Match = flightData.match(/"ivb6"\s*:\s*"([^"]+)"/);
        if (ivb6Match && ivb6Match[1]) {
          ivb6 = ivb6Match[1];
          console.log(`[EXTRACT] Found ivb6 in __next_f: ${ivb6.substring(0, 30)}...`);
        }
      }
      
      if (!token) {
        const tokenMatch = flightData.match(/"token"\s*:\s*"([^"]+)"/);
        if (tokenMatch && tokenMatch[1]) {
          token = tokenMatch[1];
          console.log(`[EXTRACT] Found token in __next_f: ${token.substring(0, 30)}...`);
        }
      }
      
      // Extract kstr and jstr (these might be in a JSON array)
      if (!kstr || !jstr) {
        // Try to find JSON array with kstr/jstr: [{"kstr":"...","jstr":"..."}]
        const jsonArrayMatch = flightData.match(/\[(\{[^}]+\})\]/);
        if (jsonArrayMatch) {
          try {
            const jsonArray = JSON.parse('[' + jsonArrayMatch[1] + ']');
            if (Array.isArray(jsonArray) && jsonArray.length > 0) {
              const firstItem = jsonArray[0];
              if (firstItem.kstr && !kstr) {
                kstr = firstItem.kstr;
                console.log(`[EXTRACT] Found kstr in JSON array: ${kstr.substring(0, 30)}...`);
              }
              if (firstItem.jstr && !jstr) {
                jstr = firstItem.jstr;
                console.log(`[EXTRACT] Found jstr in JSON array: ${jstr.substring(0, 30)}...`);
              }
            }
          } catch (e) {
            // If JSON parse fails, try regex
            const kstrMatch = flightData.match(/"kstr"\s*:\s*"([^"]+)"/);
            const jstrMatch = flightData.match(/"jstr"\s*:\s*"([^"]+)"/);
            if (kstrMatch && kstrMatch[1] && !kstr) {
              kstr = kstrMatch[1];
              console.log(`[EXTRACT] Found kstr (regex): ${kstr.substring(0, 30)}...`);
            }
            if (jstrMatch && jstrMatch[1] && !jstr) {
              jstr = jstrMatch[1];
              console.log(`[EXTRACT] Found jstr (regex): ${jstr.substring(0, 30)}...`);
            }
          }
        } else {
          // Direct regex extraction if not in array format
          if (!kstr) {
            const kstrMatch = flightData.match(/"kstr"\s*:\s*"([^"]+)"/);
            if (kstrMatch && kstrMatch[1]) {
              kstr = kstrMatch[1];
              console.log(`[EXTRACT] Found kstr directly: ${kstr.substring(0, 30)}...`);
            }
          }
          if (!jstr) {
            const jstrMatch = flightData.match(/"jstr"\s*:\s*"([^"]+)"/);
            if (jstrMatch && jstrMatch[1]) {
              jstr = jstrMatch[1];
              console.log(`[EXTRACT] Found jstr directly: ${jstr.substring(0, 30)}...`);
            }
          }
        }
      }
    }
  }
  
  // If we found a urls reference, search for it in other flight data
  if ((!kstr || !jstr) && flightDataStrings.length > 0) {
    // Look for urls reference pattern: "urls":"$10" or similar
    for (const flightData of flightDataStrings) {
      const urlsRefMatch = flightData.match(/"urls"\s*:\s*"([^"]+)"/);
      if (urlsRefMatch) {
        const urlsRef = urlsRefMatch[1].replace('$', '');
        console.log(`[EXTRACT] Found urls reference: $${urlsRef}, searching for referenced data...`);
        
        // Search for the referenced data in other flight strings
        // Format: "10:[{...}]" or similar
        for (const otherFlightData of flightDataStrings) {
          const refPattern = new RegExp(`"${urlsRef}":\\[([^\\]]+)\\]`, 'i');
          const refMatch = otherFlightData.match(refPattern);
          if (refMatch) {
            try {
              const urlsJsonStr = '[' + refMatch[1] + ']';
              const urlsArray = JSON.parse(urlsJsonStr);
              if (Array.isArray(urlsArray) && urlsArray.length > 0) {
                const firstUrl = urlsArray[0];
                if (firstUrl.kstr && !kstr) {
                  kstr = firstUrl.kstr;
                  console.log(`[EXTRACT] Found kstr from referenced urls: ${kstr.substring(0, 30)}...`);
                }
                if (firstUrl.jstr && !jstr) {
                  jstr = firstUrl.jstr;
                  console.log(`[EXTRACT] Found jstr from referenced urls: ${jstr.substring(0, 30)}...`);
                }
              }
            } catch (e) {
              // Try regex if JSON parse fails
              const kstrMatch = refMatch[1].match(/"kstr"\s*:\s*"([^"]+)"/);
              const jstrMatch = refMatch[1].match(/"jstr"\s*:\s*"([^"]+)"/);
              if (kstrMatch && kstrMatch[1] && !kstr) {
                kstr = kstrMatch[1];
                console.log(`[EXTRACT] Found kstr from referenced urls (regex): ${kstr.substring(0, 30)}...`);
              }
              if (jstrMatch && jstrMatch[1] && !jstr) {
                jstr = jstrMatch[1];
                console.log(`[EXTRACT] Found jstr from referenced urls (regex): ${jstr.substring(0, 30)}...`);
              }
            }
          }
        }
      }
    }
  }
  
  // Try to find __NEXT_DATA__ script tag
  const nextDataMatch = html.match(/<script[^>]*id="__NEXT_DATA__"[^>]*>(.*?)<\/script>/is);
  if (nextDataMatch) {
    try {
      jsonData = JSON.parse(nextDataMatch[1]);
      console.log(`[EXTRACT] Found __NEXT_DATA__ JSON`);
      
      // Navigate through the JSON structure to find the data
      if (jsonData.props && jsonData.props.pageProps) {
        const pageProps = jsonData.props.pageProps;
        
        // Look for urls array with kstr and jstr
        if (pageProps.urls && Array.isArray(pageProps.urls)) {
          const firstUrl = pageProps.urls[0];
          if (firstUrl.kstr) kstr = firstUrl.kstr;
          if (firstUrl.jstr) jstr = firstUrl.jstr;
        }
        
        // Look for datetime and ivb6 at root level
        if (pageProps.datetime) datetime = pageProps.datetime;
        if (pageProps.ivb6) ivb6 = pageProps.ivb6;
        
        // Look for token in query or props
        if (jsonData.query && jsonData.query.token) {
          token = jsonData.query.token;
        } else if (pageProps.token) {
          token = pageProps.token;
        }
      }
    } catch (err) {
      console.warn(`[EXTRACT] Failed to parse __NEXT_DATA__: ${err.message}`);
    }
  }
  
  // Fallback: try to extract directly with regex
  if (!kstr) {
    const kstrMatch = html.match(/"kstr"\s*:\s*"([^"]+)"/i);
    if (kstrMatch) kstr = kstrMatch[1];
  }
  
  if (!jstr) {
    const jstrMatch = html.match(/"jstr"\s*:\s*"([^"]+)"/i);
    if (jstrMatch) jstr = jstrMatch[1];
  }
  
  if (!datetime) {
    const datetimeMatch = html.match(/"datetime"\s*:\s*"([^"]+)"/i);
    if (datetimeMatch) datetime = datetimeMatch[1];
  }
  
  if (!ivb6) {
    const ivb6Match = html.match(/"ivb6"\s*:\s*"([^"]+)"/i);
    if (ivb6Match) ivb6 = ivb6Match[1];
  }
  
  if (!token) {
    const tokenMatch = html.match(/"token"\s*:\s*"([^"]+)"/i) || html.match(/token["']?\s*[:=]\s*["']([^"']+)["']/i);
    if (tokenMatch) token = tokenMatch[1];
  }
  
  console.log(`[EXTRACT] kstr: ${kstr ? kstr.substring(0, 30) + '...' : 'NOT FOUND'}`);
  console.log(`[EXTRACT] jstr: ${jstr ? jstr.substring(0, 30) + '...' : 'NOT FOUND'}`);
  console.log(`[EXTRACT] datetime: ${datetime || 'NOT FOUND'}`);
  console.log(`[EXTRACT] ivb6: ${ivb6 ? ivb6.substring(0, 30) + '...' : 'NOT FOUND'}`);
  console.log(`[EXTRACT] token: ${token ? token.substring(0, 30) + '...' : 'NOT FOUND'}`);
  
  if (!kstr || !jstr || !datetime || !ivb6) {
    // Save HTML for debugging
    fs.writeFileSync('player_page_debug.html', html);
    throw new Error('Could not extract required encrypted data (kstr, jstr, datetime, ivb6) from HTML. HTML saved to player_page_debug.html');
  }
  
  return { kstr, jstr, datetime, ivb6, token: token || null };
}

// Load player page and extract encrypted data (hls_tts_bypass method)
async function loadPlayerPageAndExtractInfo(playerUrl, token) {
  console.log('\n========== STEP 3: Loading Player Page ==========');
  console.log(`[PLAYER] URL: ${playerUrl}`);
  
  let browser = null;
  let html = null;
  let encryptedData = null;
  let m3u8Url = null;
  let edgeCacheToken = null;
  let segmentBaseUrl = null;
  
  try {
    // First try with Puppeteer to execute JavaScript and get dynamic data
    console.log(`[PLAYER] Launching browser to load page with JavaScript execution...`);
    browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    
    const page = await browser.newPage();
    
    // Set headers
    await page.setExtraHTTPHeaders(HEADERS);
    
    console.log(`[PLAYER] Loading player page...`);
    await page.goto(playerUrl, {
      waitUntil: 'networkidle2',
      timeout: 60000
    });
    
    // Wait a bit for JavaScript to execute and data to load
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    // Try to wait for data to be loaded - check multiple times
    console.log(`[PLAYER] Waiting for data to load...`);
    let attempts = 0;
    let foundData = false;
    while (attempts < 10 && !foundData) {
      attempts++;
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Get the full HTML after JavaScript execution
      html = await page.content();
      
      // Try to extract encrypted data from the rendered HTML
      try {
        encryptedData = extractEncryptedDataFromHTML(html);
        foundData = true;
        console.log(`[PLAYER] ✅ Successfully extracted encrypted data using Puppeteer (attempt ${attempts})`);
      } catch (err) {
        // Continue trying
        if (attempts === 10) {
          console.warn(`[PLAYER] ⚠️  Could not extract encrypted data from rendered HTML after ${attempts} attempts: ${err.message}`);
        }
      }
      
      // Also try to extract from window object
      if (!foundData) {
        try {
          // First, try to extract from __next_f directly
          const extractedData = await page.evaluate(() => {
            const result = { kstr: null, jstr: null, datetime: null, ivb6: null, token: null };
            
            // Try to get data from __next_f (Next.js Flight data)
            if (typeof self !== 'undefined' && self.__next_f && Array.isArray(self.__next_f)) {
              self.__next_f.forEach((item) => {
                if (Array.isArray(item) && item.length >= 2) {
                  const data = item[1];
                  if (typeof data === 'string') {
                    const unescaped = data.replace(/\\"/g, '"').replace(/\\\\/g, '\\');
                    const datetimeMatch = unescaped.match(/"datetime"\s*:\s*"([^"]+)"/);
                    const ivb6Match = unescaped.match(/"ivb6"\s*:\s*"([^"]+)"/);
                    const tokenMatch = unescaped.match(/"token"\s*:\s*"([^"]+)"/);
                    const kstrMatch = unescaped.match(/"kstr"\s*:\s*"([^"]+)"/);
                    const jstrMatch = unescaped.match(/"jstr"\s*:\s*"([^"]+)"/);
                    
                    if (datetimeMatch && !result.datetime) result.datetime = datetimeMatch[1];
                    if (ivb6Match && !result.ivb6) result.ivb6 = ivb6Match[1];
                    if (tokenMatch && !result.token) result.token = tokenMatch[1];
                    if (kstrMatch && !result.kstr) result.kstr = kstrMatch[1];
                    if (jstrMatch && !result.jstr) result.jstr = jstrMatch[1];
                  }
                }
              });
            }
            
            // Also try window.__NEXT_DATA__
            if (window.__NEXT_DATA__) {
              const nextData = window.__NEXT_DATA__;
              if (nextData.props && nextData.props.pageProps) {
                const pageProps = nextData.props.pageProps;
                if (pageProps.urls && Array.isArray(pageProps.urls) && pageProps.urls.length > 0) {
                  if (!result.kstr && pageProps.urls[0].kstr) result.kstr = pageProps.urls[0].kstr;
                  if (!result.jstr && pageProps.urls[0].jstr) result.jstr = pageProps.urls[0].jstr;
                }
                if (!result.datetime && pageProps.datetime) result.datetime = pageProps.datetime;
                if (!result.ivb6 && pageProps.ivb6) result.ivb6 = pageProps.ivb6;
                if (!result.token && pageProps.token) result.token = pageProps.token;
              }
            }
            
            return result;
          });
          
          if (extractedData && (extractedData.kstr || extractedData.jstr || extractedData.datetime || extractedData.ivb6)) {
            let kstr = null, jstr = null, datetime = null, ivb6 = null;
            if (extractedData.kstr) kstr = extractedData.kstr;
            if (extractedData.jstr) jstr = extractedData.jstr;
            if (extractedData.datetime) datetime = extractedData.datetime;
            if (extractedData.ivb6) ivb6 = extractedData.ivb6;
            
            if (kstr && jstr && datetime && ivb6) {
              encryptedData = { kstr, jstr, datetime, ivb6, token: extractedData.token || token || null };
              foundData = true;
              console.log(`[PLAYER] ✅ Successfully extracted encrypted data from __next_f via page.evaluate`);
            }
          }
          
          // Fallback: try window.__NEXT_DATA__
          const windowData = await page.evaluate(() => {
            if (window.__NEXT_DATA__) {
              return window.__NEXT_DATA__;
            }
            return null;
          });
          
          if (windowData) {
            console.log(`[PLAYER] Found window data (attempt ${attempts}), extracting...`);
            // Parse the window data
            const jsonData = windowData;
            
            let kstr = null, jstr = null, datetime = null, ivb6 = null;
            
            // Try different JSON structures
            if (jsonData.props && jsonData.props.pageProps) {
              const pageProps = jsonData.props.pageProps;
              
              if (pageProps.urls && Array.isArray(pageProps.urls)) {
                const firstUrl = pageProps.urls[0];
                if (firstUrl.kstr) kstr = firstUrl.kstr;
                if (firstUrl.jstr) jstr = firstUrl.jstr;
              }
              
              if (pageProps.datetime) datetime = pageProps.datetime;
              if (pageProps.ivb6) ivb6 = pageProps.ivb6;
            }
            
            // Try direct access if props structure doesn't exist
            if (!kstr && !jstr) {
              if (jsonData.kstr) kstr = jsonData.kstr;
              if (jsonData.jstr) jstr = jsonData.jstr;
              if (jsonData.datetime) datetime = jsonData.datetime;
              if (jsonData.ivb6) ivb6 = jsonData.ivb6;
            }
            
            if (kstr && jstr && datetime && ivb6) {
              encryptedData = { kstr, jstr, datetime, ivb6, token: token || null };
              foundData = true;
              console.log(`[PLAYER] ✅ Successfully extracted encrypted data from window object (attempt ${attempts})`);
            }
          }
        } catch (err2) {
          // Continue to next attempt
          if (attempts === 10) {
            console.warn(`[PLAYER] ⚠️  Could not extract from window object after ${attempts} attempts: ${err2.message}`);
          }
        }
      }
    }
    
    await browser.close();
    browser = null;
  } catch (puppeteerErr) {
    console.warn(`[PLAYER] ⚠️  Puppeteer method failed: ${puppeteerErr.message}`);
    console.log(`[PLAYER] Falling back to static HTML fetch...`);
    
    if (browser) {
      await browser.close();
      browser = null;
    }
    
    // Fallback to static fetch
    try {
      console.log(`[FETCH] Making GET request to player page`);
      const res = await fetch(playerUrl, {
        headers: {
          ...HEADERS,
          'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'accept-language': 'en-US,en;q=0.9'
        }
      });
      
      console.log(`[FETCH] Response status: ${res.status}`);
      
      if (res.status !== 200) {
        const errorText = await res.text();
        throw new Error(`Failed to load player page: ${res.status} - ${errorText.substring(0, 200)}`);
      }
      
      html = await res.text();
      console.log(`[PLAYER] Page loaded (${html.length} bytes)`);
      
      // Try to extract encrypted data from static HTML
      if (!encryptedData) {
        try {
          encryptedData = extractEncryptedDataFromHTML(html);
          console.log(`[PLAYER] ✅ Successfully extracted encrypted data from static HTML`);
        } catch (err) {
          console.warn(`[PLAYER] ⚠️  Could not extract encrypted data: ${err.message}`);
          encryptedData = null;
        }
      }
    } catch (fetchErr) {
      console.warn(`[PLAYER] Static fetch failed: ${fetchErr.message}`);
      // Continue with whatever HTML we have
    }
  }
  
  // Extract M3U8 URL from HTML/JavaScript (using whatever HTML we have)
  if (!html) {
    // If we still don't have HTML, try one more static fetch
    try {
      const res = await fetch(playerUrl, {
        headers: {
          ...HEADERS,
          'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'accept-language': 'en-US,en;q=0.9'
        }
      });
      if (res.status === 200) {
        html = await res.text();
      }
    } catch (err) {
      // Ignore
    }
  }
  
  if (html) {
    // Extract M3U8 URL from HTML/JavaScript
    let m3u8Url = null;
    let edgeCacheToken = null;
    
    // Look for M3U8 URLs in the HTML
    const m3u8Patterns = [
      /(https?:\/\/[^\s"']+\.m3u8[^\s"']*)/gi,
      /(https?:\/\/[^\s"']+\.m3u8)/gi,
      /["']([^"']+\.m3u8[^"']*)["']/gi,
      /src["']?\s*[:=]\s*["']([^"']+\.m3u8[^"']*)["']/gi,
      /url["']?\s*[:=]\s*["']([^"']+\.m3u8[^"']*)["']/gi
    ];
    
    for (const pattern of m3u8Patterns) {
      const matches = html.matchAll(pattern);
      for (const match of matches) {
        const url = match[1];
        if (url && url.includes('.m3u8')) {
          m3u8Url = url;
          console.log(`[PLAYER] Found M3U8 URL: ${m3u8Url}`);
          break;
        }
      }
      if (m3u8Url) break;
    }
    
    // Look for edge-cache-token in HTML/JS
    const tokenPatterns = [
      /edge[-_]cache[-_]token["']?\s*[:=]\s*["']([^"']+)["']/gi,
      /token["']?\s*[:=]\s*["']([^"']{20,})["']/gi,
      /["']edge-cache-token["']\s*:\s*["']([^"']+)["']/gi
    ];
    
    for (const pattern of tokenPatterns) {
      const matches = html.matchAll(pattern);
      for (const match of matches) {
        const foundToken = match[1];
        if (foundToken && foundToken.length > 20) {
          edgeCacheToken = foundToken;
          console.log(`[PLAYER] Found edge-cache-token: ${edgeCacheToken.substring(0, 50)}...`);
          break;
        }
      }
      if (edgeCacheToken) break;
    }
    
    // Look for transcoded-videos segment URLs to extract base path
    let segmentBaseUrl = null;
    const segmentUrlPatterns = [
      /(https?:\/\/transcoded-videos\.classx\.co\.in\/[^\s"']+)\/[^\/\s"']+\.ts[^"']*/gi,
      /(https?:\/\/transcoded-videos\.classx\.co\.in\/[^\s"']+)\/[^\/\s"']+\.tsf[^"']*/gi,
      /transcoded-videos\.classx\.co\.in\/([^\s"']+\/[^\s"']+)\/[^\/\s"']+\.ts/gi
    ];
    
    for (const pattern of segmentUrlPatterns) {
      const matches = html.matchAll(pattern);
      for (const match of matches) {
        const url = match[1];
        if (url && url.includes('transcoded-videos')) {
          // Extract base URL (everything before the filename)
          const urlObj = new URL(url.startsWith('http') ? url : `https://${url}`);
          const pathParts = urlObj.pathname.split('/');
          pathParts.pop(); // Remove filename
          segmentBaseUrl = `${urlObj.origin}${pathParts.join('/')}`;
          console.log(`[PLAYER] Found segment base URL: ${segmentBaseUrl}`);
          break;
        } else if (url && !url.startsWith('http')) {
          // It's a path, construct full URL
          segmentBaseUrl = `https://transcoded-videos.classx.co.in/${url}`;
          console.log(`[PLAYER] Found segment base path: ${segmentBaseUrl}`);
          break;
        }
      }
      if (segmentBaseUrl) break;
    }
    
    // Look in JavaScript variables
    const jsVarPatterns = [
      /var\s+[\w_]*m3u8[\w_]*\s*=\s*["']([^"']+\.m3u8[^"']*)["']/gi,
      /let\s+[\w_]*m3u8[\w_]*\s*=\s*["']([^"']+\.m3u8[^"']*)["']/gi,
      /const\s+[\w_]*m3u8[\w_]*\s*=\s*["']([^"']+\.m3u8[^"']*)["']/gi,
      /videoUrl\s*[:=]\s*["']([^"']+\.m3u8[^"']*)["']/gi,
      /source\s*[:=]\s*["']([^"']+\.m3u8[^"']*)["']/gi
    ];
    
    for (const pattern of jsVarPatterns) {
      const matches = html.matchAll(pattern);
      for (const match of matches) {
        const url = match[1];
        if (url && url.includes('.m3u8')) {
          m3u8Url = url;
          console.log(`[PLAYER] Found M3U8 URL in JS variable: ${m3u8Url}`);
          break;
        }
      }
      if (m3u8Url) break;
    }
    
    // If still no M3U8 URL, try to find it in script tags
    if (!m3u8Url) {
      const scriptMatches = html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi);
      for (const scriptMatch of scriptMatches) {
        const scriptContent = scriptMatch[1];
        const urlMatch = scriptContent.match(/(https?:\/\/[^\s"']+\.m3u8[^\s"']*)/i);
        if (urlMatch) {
          m3u8Url = urlMatch[1];
          console.log(`[PLAYER] Found M3U8 URL in script tag: ${m3u8Url}`);
          break;
        }
      }
    }
    
    // If we still don't have encrypted data, try one more time with HTML
    if (!encryptedData && html) {
      try {
        encryptedData = extractEncryptedDataFromHTML(html);
        console.log(`[PLAYER] ✅ Successfully extracted encrypted data from HTML`);
      } catch (err) {
        console.warn(`[PLAYER] ⚠️  Could not extract encrypted data: ${err.message}`);
        encryptedData = null;
      }
    }
  }
  
  console.log(`[PLAYER] First 1000 chars of HTML:`, html ? html.substring(0, 1000) : 'N/A');
  
  return { 
    html: html || '', 
    encryptedData,
    m3u8Url: m3u8Url || null,  // Keep M3U8 URL for fallback
    edgeCacheToken: edgeCacheToken || token || (encryptedData ? encryptedData.token : null),
    segmentBaseUrl: segmentBaseUrl || null
  };
}

// Decrypt jstr to get M3U8 playlist (hls_tts_bypass method)
async function decryptM3U8FromJstr(encryptedData, token) {
  console.log('\n========== STEP 4: Decrypting M3U8 from jstr ==========');
  
  try {
    const { jstr, datetime, ivb6 } = encryptedData;
    
    if (!jstr || !datetime || !ivb6) {
      throw new Error('Missing required data: jstr, datetime, or ivb6');
    }
    
    // Derive decryption key from datetime and token
    console.log(`[M3U8] Deriving key from datetime and token...`);
    console.log(`[M3U8] datetime: ${datetime}`);
    console.log(`[M3U8] token: ${token ? token.substring(0, 30) + '...' : 'NOT FOUND'}`);
    const { key, keyBase64 } = getDataEncKey(datetime, token);
    
    // Decrypt jstr using the derived key and ivb6
    // jstr is the encrypted M3U8 playlist
    console.log(`[M3U8] Decrypting jstr with key and ivb6...`);
    console.log(`[M3U8] jstr length: ${jstr ? jstr.length : 0} chars`);
    console.log(`[M3U8] ivb6: ${ivb6 ? ivb6.substring(0, 30) + '...' : 'NOT FOUND'}`);
    const playlist = decryptData(jstr, key, ivb6);
    
    console.log(`[M3U8] ✅ Playlist decrypted (${playlist.length} bytes)`);
    console.log(`[M3U8] First 500 chars:`, playlist.substring(0, 500));
    
    return playlist;
  } catch (err) {
    console.error('[M3U8] Error decrypting playlist:', err);
    throw err;
  }
}

// Download M3U8 playlist (fallback method - kept for compatibility)
async function downloadM3U8(m3u8Url, token) {
  console.log('\n========== STEP 4: Downloading M3U8 Playlist ==========');
  console.log(`[M3U8] URL: ${m3u8Url}`);
  
  const headers = { ...HEADERS };
  if (token) {
    headers['edge-cache-token'] = token;
    console.log(`[M3U8] Using token: ${token.substring(0, 50)}...`);
  }
  
  try {
    console.log(`[FETCH] Making GET request to: ${m3u8Url}`);
    const res = await fetch(m3u8Url, { headers });
    
    console.log(`[FETCH] Response status: ${res.status}`);
    
    if (res.status !== 200) {
      const errorText = await res.text();
      throw new Error(`Failed to download M3U8: ${res.status} - ${errorText.substring(0, 200)}`);
    }
    
    const playlist = await res.text();
    
    console.log(`[M3U8] Playlist downloaded (${playlist.length} bytes)`);
    console.log(`[M3U8] First 500 chars:`, playlist.substring(0, 500));
    
    return playlist;
  } catch (err) {
    console.error('[M3U8] Error downloading playlist:', err);
    throw err;
  }
}

// Parse M3U8 to extract segments and key info
function parseM3U8(playlist, baseUrl) {
  console.log('\n========== STEP 5: Parsing M3U8 Playlist ==========');
  
  const lines = playlist.split('\n');
  const segments = [];
  let currentKey = null;
  let keyUrl = null;
  let keyIV = null;
  let baseM3U8Url = baseUrl ? baseUrl.substring(0, baseUrl.lastIndexOf('/') + 1) : '';
  
  // Try to detect actual segment base URL from segment URLs
  let actualSegmentBaseUrl = null;
  
  // Track MEDIA-SEQUENCE for IV calculation (HLS standard: IV = baseIV + sequence)
  let mediaSequence = 0;
  let segmentSequence = 0;
  
  console.log(`[PARSE] Base URL for segments: ${baseM3U8Url}`);
  console.log(`[PARSE] Total lines in playlist: ${lines.length}`);
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    
    // Check for MEDIA-SEQUENCE
    if (line.startsWith('#EXT-X-MEDIA-SEQUENCE:')) {
      const seqMatch = line.match(/MEDIA-SEQUENCE:\s*(\d+)/);
      if (seqMatch) {
        mediaSequence = parseInt(seqMatch[1], 10);
        console.log(`[PARSE] Media sequence: ${mediaSequence}`);
      }
    }
    
    if (line.startsWith('#EXT-X-KEY:')) {
      console.log(`[PARSE] Found key line: ${line}`);
      const keyMatch = line.match(/URI="([^"]+)"/);
      const ivMatch = line.match(/IV=0x([0-9a-fA-F]+)/);
      const methodMatch = line.match(/METHOD=([^,]+)/);
      
      if (keyMatch) {
        keyUrl = keyMatch[1];
        console.log(`[PARSE] Key URL: ${keyUrl}`);
      }
      if (ivMatch) {
        keyIV = ivMatch[1];
        console.log(`[PARSE] Key IV (base): ${keyIV}`);
      }
      if (methodMatch) {
        console.log(`[PARSE] Encryption method: ${methodMatch[1]}`);
      }
      
      currentKey = { url: keyUrl, iv: keyIV, baseIV: keyIV };
    }
    
    if (line && !line.startsWith('#') && (line.includes('.ts') || line.includes('.tsf') || line.includes('.tsa') || line.includes('.tsb') || line.includes('.tsc') || line.includes('.tsd') || line.includes('.tse'))) {
      let segmentUrl;
      if (line.startsWith('http')) {
        segmentUrl = line;
        // Extract base URL from full segment URL
        const urlObj = new URL(segmentUrl);
        const pathParts = urlObj.pathname.split('/');
        pathParts.pop(); // Remove filename
        actualSegmentBaseUrl = `${urlObj.origin}${pathParts.join('/')}`;
        console.log(`[PARSE] Detected actual segment base URL from segment: ${actualSegmentBaseUrl}`);
      } else {
        segmentUrl = baseM3U8Url + line;
      }
      
      // Use IV from M3U8 directly (as per markdown documentation)
      // The IV in M3U8 is used for all segments
      segments.push({
        url: segmentUrl,
        key: currentKey,
        sequence: mediaSequence + segmentSequence
      });
      segmentSequence++;
      console.log(`[PARSE] Found segment ${segments.length}: ${line}`);
    }
  }
  
  console.log(`[PARSE] Total segments found: ${segments.length}`);
  console.log(`[PARSE] Key info:`, currentKey);
  if (actualSegmentBaseUrl) {
    console.log(`[PARSE] Actual segment base URL: ${actualSegmentBaseUrl}`);
  }
  
  return { segments, keyInfo: currentKey, actualSegmentBaseUrl };
}

// encodeBytes function from worker script
function encodeBytes(encodedStr) {
  const key = 7;
  let step1 = Buffer.from(encodedStr, 'base64').toString('utf8').split("").reverse().join("");
  let step2 = step1.split("").map((c) => c.charCodeAt(0));
  let step3 = step2.map((c) => c ^ key);
  let step4 = step3.reverse();
  let step5 = step4.map((c) => String.fromCharCode(c - 1));
  return step5.join("");
}

// Extract and transform key identifier using bd() function from PNG
async function getKeyTransformationFunction(videoData) {
  console.log('\n========== STEP 5.5: Extracting Key Transformation Function ==========');
  
  // Get the PNG URL from video data (uhs_version determines the path)
  let pngUrl = null;
  if (videoData.data) {
    const uhsVersion = videoData.data.uhs_version || '4.00';
    const versionNum = parseFloat(uhsVersion);
    const recDomain = videoData.data.rec_domain || 'harkirat.classx.co.in';
    
    // Determine image path based on version
    let imagePath = '';
    if (versionNum >= 4) {
      imagePath = 'video1-uhs4.png';
    } else if (versionNum >= 3) {
      imagePath = 'video1-uhs3.png';
    } else {
      imagePath = 'video1.png';
    }
    
    // Determine watermark type from domain
    let watermark = 'watermark-2';
    if (recDomain.includes('harkirat')) {
      watermark = 'watermark-2';
    } else {
      watermark = 'awsa';
    }
    
    pngUrl = `https://appx-play.classx.co.in/uhs-hls-player/images/${watermark}/${imagePath}`;
    console.log(`[TRANSFORM] PNG URL: ${pngUrl}`);
  }
  
  if (!pngUrl) {
    // Fallback to default
    pngUrl = 'https://appx-play.classx.co.in/uhs-hls-player/images/watermark-2/video1-uhs4.png';
    console.log(`[TRANSFORM] Using default PNG URL: ${pngUrl}`);
  }
  
  try {
    console.log(`[FETCH] Downloading encrypted script from PNG...`);
    const res = await fetch(pngUrl, { headers: HEADERS });
    
    if (res.status !== 200) {
      throw new Error(`Failed to download PNG: ${res.status}`);
    }
    
    const encryptedData = await res.text();
    console.log(`[TRANSFORM] Downloaded encrypted data (${encryptedData.length} chars)`);
    
    // Parse the JSON (it's actually JSON, not a real PNG)
    let encryptedJson;
    try {
      encryptedJson = JSON.parse(encryptedData);
      console.log(`[TRANSFORM] Parsed encrypted JSON`);
    } catch (e) {
      // If it's not JSON, it might be the encrypted string directly
      encryptedJson = { ct: encryptedData };
    }
    
    // Decrypt using SJCL (same as worker script)
    console.log(`[TRANSFORM] Decrypting with SJCL...`);
    const password = encodeBytes("ZXZ2fjU0Mw==");
    console.log(`[TRANSFORM] Decryption password: ${password.substring(0, 10)}...`);
    
    let decryptedBase64;
    try {
      decryptedBase64 = sjcl.decrypt(password, JSON.stringify(encryptedJson));
      console.log(`[TRANSFORM] ✅ Decryption successful`);
    } catch (err) {
      console.error(`[TRANSFORM] ❌ SJCL decryption failed:`, err.message);
      throw new Error(`Decryption failed: ${err.message}`);
    }
    
    // Decompress using pako (zlib inflate)
    console.log(`[TRANSFORM] Decompressing with pako...`);
    const compressedBytes = Uint8Array.from(
      Buffer.from(decryptedBase64, 'base64'),
      (c) => c
    );
    
    const decompressed = pako.inflate(compressedBytes);
    const originalScript = Buffer.from(decompressed).toString('utf8');
    
    console.log(`[TRANSFORM] ✅ Decompression successful`);
    console.log(`[TRANSFORM] Script length: ${originalScript.length} chars`);
    console.log(`[TRANSFORM] First 500 chars: ${originalScript.substring(0, 500)}`);
    
    // Save decrypted script for inspection
    fs.writeFileSync('decrypted_script.js', originalScript);
    console.log(`[TRANSFORM] Saved decrypted script to decrypted_script.js`);
    
    // Extract bd() function from the script
    // Look for function bd or const bd or var bd
    console.log(`[TRANSFORM] Extracting bd() function...`);
    
    // Try to find bd function definition
    const bdPatterns = [
      /function\s+bd\s*\([^)]*\)\s*\{[^}]*\}/g,
      /const\s+bd\s*=\s*function\s*\([^)]*\)\s*\{[^}]*\}/g,
      /var\s+bd\s*=\s*function\s*\([^)]*\)\s*\{[^}]*\}/g,
      /const\s+bd\s*=\s*\([^)]*\)\s*=>\s*\{[^}]*\}/g,
      /bd\s*[:=]\s*function\s*\([^)]*\)\s*\{[^}]*\}/g
    ];
    
    let bdFunction = null;
    for (const pattern of bdPatterns) {
      const match = originalScript.match(pattern);
      if (match) {
        console.log(`[TRANSFORM] Found bd function with pattern`);
        bdFunction = match[0];
        break;
      }
    }
    
    if (!bdFunction) {
      // Try to extract a larger context around "bd"
      const bdContext = originalScript.match(/bd[^}]*\{[^}]*\}/);
      if (bdContext) {
        console.log(`[TRANSFORM] Found bd context`);
        bdFunction = bdContext[0];
      }
    }
    
    if (bdFunction) {
      console.log(`[TRANSFORM] ✅ Found bd function: ${bdFunction.substring(0, 200)}...`);
      
      // Create a sandboxed environment to execute and extract the function
      try {
        // Create a context with minimal globals
        const vm = require('vm');
        const context = {
          console: console,
          Buffer: Buffer,
          require: require
        };
        
        // Execute the script in the context to get bd function
        vm.createContext(context);
        vm.runInContext(originalScript, context);
        
        if (context.bd && typeof context.bd === 'function') {
          console.log(`[TRANSFORM] ✅ Successfully extracted bd() function`);
          return context.bd;
        } else {
          console.warn(`[TRANSFORM] ⚠️  bd function not found in context after execution`);
        }
      } catch (err) {
        console.warn(`[TRANSFORM] ⚠️  Could not execute script in VM: ${err.message}`);
      }
    } else {
      console.warn(`[TRANSFORM] ⚠️  Could not find bd function in script`);
    }
    
    return null;
  } catch (err) {
    console.error('[TRANSFORM] Error extracting transformation function:', err);
    return null;
  }
}

// Transform key identifier using bd() function
function transformKeyIdentifier(keyIdentifier, bdFunction) {
  if (bdFunction && typeof bdFunction === 'function') {
    return bdFunction(keyIdentifier);
  }
  // Fallback: return as-is (might work in some cases)
  return keyIdentifier;
}

// Try to derive segment base URL from video data
// Pattern from HAR: https://transcoded-videos.classx.co.in/videos/harkirat-data/511504-1759062548/hls-drm-a9230d/360p/
function deriveSegmentBaseUrl(videoData, quality = '360p') {
  if (!videoData || !videoData.data) return null;
  
  const data = videoData.data;
  const recDomain = data.rec_domain || 'harkirat.classx.co.in';
  const domainName = recDomain.split('.')[0]; // e.g., "harkirat"
  const videoId = data.id;
  const courseId = data.course_id;
  const strtotime = data.strtotime;
  
  // Pattern: /videos/{domain}-data/{someId}-{timestamp}/hls-drm-{hash}/{quality}/
  // From HAR: /videos/harkirat-data/511504-1759062548/hls-drm-a9230d/360p/
  // The "511504-1759062548" might be course_id-strtotime or video_id-strtotime
  // The "a9230d" hash is unknown, but we can try common patterns
  
  const baseUrlsToTry = [];
  
  // Try course_id-strtotime pattern
  if (courseId && strtotime) {
    baseUrlsToTry.push(
      `https://transcoded-videos.classx.co.in/videos/${domainName}-data/${courseId}-${strtotime}/hls-drm-*/${quality}/`
    );
  }
  
  // Try video_id-strtotime pattern
  if (videoId && strtotime) {
    baseUrlsToTry.push(
      `https://transcoded-videos.classx.co.in/videos/${domainName}-data/${videoId}-${strtotime}/hls-drm-*/${quality}/`
    );
  }
  
  // Try video_id only
  if (videoId) {
    baseUrlsToTry.push(
      `https://transcoded-videos.classx.co.in/videos/${domainName}-data/${videoId}/hls-drm-*/${quality}/`
    );
  }
  
  console.log(`[DERIVE] Generated ${baseUrlsToTry.length} potential segment base URL patterns`);
  return baseUrlsToTry;
}

// Try to decrypt encrypted_links (placeholder - actual decryption method unknown)
async function tryDecryptEncryptedLinks(encryptedLinks, cookieValue, ivString) {
  console.log(`[DECRYPT] Attempting to decrypt encrypted_links...`);
  console.log(`[DECRYPT] Found ${encryptedLinks.length} encrypted links`);
  
  // The encrypted_links format is: "encrypted_data:base64_iv"
  // The suffix decodes to "fedcba9876543210" which might be an IV
  // Actual decryption method is unknown - might require k1() function or other method
  
  for (let i = 0; i < encryptedLinks.length; i++) {
    const link = encryptedLinks[i];
    if (link.path) {
      console.log(`[DECRYPT] Encrypted link ${i + 1} (${link.quality}): ${link.path.substring(0, 100)}...`);
      // TODO: Implement actual decryption if method is found
    }
  }
  
  return null; // Return null if decryption fails
}

// Extract keys from videojs player using Puppeteer
async function extractKeysFromVideojs(playerUrl, token) {
  console.log('\n========== STEP 5.5: Extracting Keys from VideoJS ==========');
  console.log(`[VIDEOJS] Player URL: ${playerUrl}`);
  
  let browser = null;
  try {
    console.log(`[VIDEOJS] Launching browser...`);
    browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    
    const page = await browser.newPage();
    
    // Set headers
    await page.setExtraHTTPHeaders(HEADERS);
    
    console.log(`[VIDEOJS] Loading player page...`);
    await page.goto(playerUrl, {
      waitUntil: 'networkidle2',
      timeout: 60000
    });
    
    console.log(`[VIDEOJS] Waiting for videojs to initialize...`);
    
    // Wait for videojs to be available and player to be ready
    await page.waitForFunction(() => {
      return typeof videojs !== 'undefined' && 
             Object.keys(videojs.getPlayers()).length > 0;
    }, { timeout: 30000 });
    
    console.log(`[VIDEOJS] VideoJS found, waiting for HLS to load...`);
    
    // Try to trigger video playback
    try {
      await page.evaluate(() => {
        const playerKeys = Object.keys(videojs.getPlayers());
        if (playerKeys.length > 0) {
          const player = videojs.getPlayers()[playerKeys[0]];
          // Try to play the video
          if (player && typeof player.play === 'function') {
            player.play().catch(() => {});
          }
        }
      });
      console.log(`[VIDEOJS] Attempted to start video playback`);
    } catch (err) {
      console.log(`[VIDEOJS] Could not trigger playback: ${err.message}`);
    }
    
    // Wait for video to start playing and segments to load
    await page.waitForFunction(() => {
      try {
        const playerKeys = Object.keys(videojs.getPlayers());
        if (playerKeys.length === 0) return false;
        
        const player = videojs.getPlayers()[playerKeys[0]];
        const tech = player.tech();
        if (!tech || !tech.hls) return false;
        
        // Check if segments are available
        const playlists = tech.hls.playlists;
        if (!playlists) return false;
        
        // Try different ways to access segments
        let mediaPlaylist = playlists.media_;
        
        if (!mediaPlaylist && playlists.master) {
          if (playlists.master.playlists && playlists.master.playlists.length > 0) {
            mediaPlaylist = playlists.master.playlists[0];
          }
        }
        
        if (!mediaPlaylist) {
          // Try to find any playlist with segments
          const allPlaylists = playlists.master ? playlists.master.playlists : [];
          for (const pl of allPlaylists) {
            if (pl && pl.segments && pl.segments.length > 0) {
              mediaPlaylist = pl;
              break;
            }
          }
        }
        
        if (!mediaPlaylist) return false;
        
        const segments = mediaPlaylist.segments;
        return segments && segments.length > 0;
      } catch (e) {
        return false;
      }
    }, { timeout: 90000, polling: 2000 });
    
    console.log(`[VIDEOJS] Segments loaded, extracting keys...`);
    
    // Wait for HLS tech to be available and segments to load
    const keysData = await page.evaluate(async () => {
      // Wait a bit more for segments to fully load
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      try {
        // Get the videojs player instance
        const playerKeys = Object.keys(videojs.getPlayers());
        if (playerKeys.length === 0) {
          throw new Error('No videojs players found');
        }
        
        const player = videojs.getPlayers()[playerKeys[0]];
        
        // Get the HLS tech
        const tech = player.tech();
        if (!tech || !tech.hls) {
          throw new Error('HLS tech not found');
        }
        
        const playlists = tech.hls.playlists;
        if (!playlists) {
          throw new Error('HLS playlists not found');
        }
        
        // Try different ways to access segments
        let segments = null;
        let mediaPlaylist = playlists.media_;
        
        if (!mediaPlaylist && playlists.master) {
          // Try to get from master playlist
          if (playlists.master.playlists && playlists.master.playlists.length > 0) {
            mediaPlaylist = playlists.master.playlists[0];
          }
        }
        
        if (!mediaPlaylist) {
          // Try to find any playlist with segments
          const allPlaylists = playlists.master ? playlists.master.playlists : [];
          for (const pl of allPlaylists) {
            if (pl && pl.segments && pl.segments.length > 0) {
              mediaPlaylist = pl;
              break;
            }
          }
        }
        
        if (!mediaPlaylist) {
          throw new Error('Media playlist not found. Available: ' + JSON.stringify(Object.keys(playlists)));
        }
        
        segments = mediaPlaylist.segments;
        if (!segments || segments.length === 0) {
          throw new Error('No segments found');
        }
        
        console.log(`Found ${segments.length} segments`);
        
        // Extract unique keys from segments
        const keys = [];
        const keyMap = new Map();
        
        segments.forEach((segment, index) => {
          if (segment.key) {
            const keyUri = segment.key.resolvedUri || segment.key.uri;
            
            if (!keyMap.has(keyUri)) {
              keyMap.set(keyUri, true);
              keys.push({
                uri: segment.key.uri,
                resolvedUri: keyUri,
                method: segment.key.method,
                iv: segment.key.iv,
                segmentIndex: index,
                segmentUrl: segment.resolvedUri || segment.uri
              });
            }
          }
        });
        
        console.log(`Found ${keys.length} unique keys`);
        
        // Download the actual key data
        const keysWithData = [];
        for (let i = 0; i < keys.length; i++) {
          const key = keys[i];
          try {
            const response = await fetch(key.resolvedUri);
            if (response.ok) {
              const keyData = await response.arrayBuffer();
              const keyBuffer = new Uint8Array(keyData);
              const keyHex = Array.from(keyBuffer)
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
              
              keysWithData.push({
                ...key,
                keyData: Array.from(keyBuffer), // Convert to array for JSON serialization
                keyHex: keyHex,
                keyLength: keyBuffer.length
              });
            } else {
              console.warn(`Failed to download key ${i + 1}: ${response.status}`);
              keysWithData.push(key);
            }
          } catch (err) {
            console.warn(`Error downloading key ${i + 1}: ${err.message}`);
            keysWithData.push(key);
          }
        }
        
        return {
          playerId: playerKeys[0],
          segmentCount: segments.length,
          keys: keysWithData,
          segments: segments.map((seg, idx) => ({
            index: idx,
            uri: seg.uri,
            resolvedUri: seg.resolvedUri,
            key: seg.key ? {
              uri: seg.key.uri,
              resolvedUri: seg.key.resolvedUri,
              method: seg.key.method,
              iv: seg.key.iv
            } : null
          }))
        };
      } catch (err) {
        return {
          error: err.message,
          stack: err.stack
        };
      }
    });
    
    if (keysData.error) {
      throw new Error(`Failed to extract keys from videojs: ${keysData.error}`);
    }
    
    console.log(`[VIDEOJS] ✅ Successfully extracted ${keysData.keys.length} key(s) from ${keysData.segmentCount} segments`);
    
    // Get the first key with actual key data
    const keyWithData = keysData.keys.find(k => k.keyData);
    if (!keyWithData || !keyWithData.keyData) {
      throw new Error('No key data found. Keys may not have been downloaded successfully.');
    }
    
    // Convert array back to Buffer
    const keyBuffer = Buffer.from(keyWithData.keyData);
    console.log(`[VIDEOJS] Using key: ${keyWithData.keyHex}`);
    console.log(`[VIDEOJS] Key length: ${keyBuffer.length} bytes`);
    
    if (keyBuffer.length !== 16) {
      console.warn(`[VIDEOJS] ⚠️  WARNING: Expected 16 bytes, got ${keyBuffer.length}`);
    }
    
    return {
      key: keyBuffer,
      keyInfo: keyWithData,
      allKeys: keysData.keys,
      segments: keysData.segments
    };
    
  } catch (err) {
    console.error('[VIDEOJS] Error extracting keys:', err);
    throw err;
  } finally {
    if (browser) {
      await browser.close();
      console.log(`[VIDEOJS] Browser closed`);
    }
  }
}

// Decrypt kstr to get decryption key (hls_tts_bypass method)
async function decryptKeyFromKstr(encryptedData, token) {
  console.log('\n========== STEP 6: Decrypting Key from kstr ==========');
  
  try {
    const { kstr, datetime, ivb6 } = encryptedData;
    
    if (!kstr || !datetime || !ivb6) {
      throw new Error('Missing required data: kstr, datetime, or ivb6');
    }
    
    // Derive decryption key from datetime and token
    console.log(`[KEY] Deriving key from datetime and token...`);
    console.log(`[KEY] datetime: ${datetime}`);
    console.log(`[KEY] token: ${token ? token.substring(0, 30) + '...' : 'NOT FOUND'}`);
    const { key, keyBase64 } = getDataEncKey(datetime, token);
    
    // Decrypt kstr using the derived key and ivb6
    // kstr is the encrypted video decryption key
    console.log(`[KEY] Decrypting kstr with key and ivb6...`);
    console.log(`[KEY] kstr length: ${kstr ? kstr.length : 0} chars`);
    console.log(`[KEY] ivb6: ${ivb6 ? ivb6.substring(0, 30) + '...' : 'NOT FOUND'}`);
    const decryptedKstr = decryptData(kstr, key, ivb6);
    
    // The decrypted kstr should be the actual AES-128 key (16 bytes)
    // It might be in hex format or base64
    let keyBuffer;
    try {
      // Try to parse as hex
      keyBuffer = Buffer.from(decryptedKstr.trim(), 'hex');
      if (keyBuffer.length === 16) {
        console.log(`[KEY] ✅ Key parsed as hex (16 bytes)`);
      } else {
        throw new Error('Not hex or wrong length');
      }
    } catch (err) {
      // Try base64
      try {
        keyBuffer = Buffer.from(decryptedKstr.trim(), 'base64');
        if (keyBuffer.length === 16) {
          console.log(`[KEY] ✅ Key parsed as base64 (16 bytes)`);
        } else {
          // If not 16 bytes, use first 16 bytes or pad
          if (keyBuffer.length > 16) {
            keyBuffer = keyBuffer.slice(0, 16);
          } else {
            keyBuffer = Buffer.concat([keyBuffer, Buffer.alloc(16 - keyBuffer.length, 0)]);
          }
          console.log(`[KEY] ✅ Key adjusted to 16 bytes`);
        }
      } catch (err2) {
        // Try as raw string (UTF-8)
        keyBuffer = Buffer.from(decryptedKstr.trim(), 'utf8');
        if (keyBuffer.length > 16) {
          keyBuffer = keyBuffer.slice(0, 16);
        } else if (keyBuffer.length < 16) {
          keyBuffer = Buffer.concat([keyBuffer, Buffer.alloc(16 - keyBuffer.length, 0)]);
        }
        console.log(`[KEY] ✅ Key parsed as UTF-8 (adjusted to 16 bytes)`);
      }
    }
    
    console.log(`[KEY] ✅ Decrypted key: ${keyBuffer.toString('hex')}`);
    console.log(`[KEY] Key length: ${keyBuffer.length} bytes`);
    
    return keyBuffer;
  } catch (err) {
    console.error('[KEY] Error decrypting key:', err);
    throw err;
  }
}

// Download decryption key (fallback method - kept for compatibility)
async function downloadKey(keyIdentifier, token, videoData, segmentBaseUrl = null, m3u8Url = null) {
  console.log('\n========== STEP 6: Downloading Decryption Key ==========');
  console.log(`[KEY] Key identifier from M3U8: ${keyIdentifier}`);
  
  // Try to derive segment base URL from video data if not provided
  if (!segmentBaseUrl && videoData && videoData.data) {
    console.log(`[KEY] Attempting to derive segment base URL from video data...`);
    const derivedUrls = deriveSegmentBaseUrl(videoData);
    if (derivedUrls && derivedUrls.length > 0) {
      console.log(`[KEY] Derived ${derivedUrls.length} potential segment base URL patterns`);
      // Note: These contain wildcards, so we can't use them directly
      // But we can try to construct actual URLs by trying common hash patterns
    }
    
    // Also try to decrypt encrypted_links
    if (videoData.data.encrypted_links && videoData.data.encrypted_links.length > 0) {
      const decryptedUrl = await tryDecryptEncryptedLinks(
        videoData.data.encrypted_links,
        videoData.data.cookie_value,
        videoData.data.iv_string
      );
      if (decryptedUrl) {
        console.log(`[KEY] ✅ Decrypted URL from encrypted_links: ${decryptedUrl}`);
        // Extract base URL from decrypted URL
        const urlObj = new URL(decryptedUrl);
        const pathParts = urlObj.pathname.split('/');
        pathParts.pop();
        segmentBaseUrl = `${urlObj.origin}${pathParts.join('/')}/`;
        console.log(`[KEY] Using segment base URL from decrypted link: ${segmentBaseUrl}`);
      }
    }
  }
  
  // Try to get transformation function
  const transformFn = await getKeyTransformationFunction(videoData);
  
  // Transform the key identifier
  let transformedKey = transformKeyIdentifier(keyIdentifier, transformFn);
  if (transformedKey === keyIdentifier) {
    console.log(`[KEY] ⚠️  No transformation function found, using identifier as-is`);
    // Fallback: Use transformed key from HAR analysis if we know the mapping
    if (keyIdentifier === '1705855799') {
      transformedKey = '5561f02e2048a11642632dbae2ca8be3';
      console.log(`[KEY] Using transformed key from HAR analysis: ${transformedKey}`);
    }
  } else {
    console.log(`[KEY] ✅ Transformed key: ${keyIdentifier} -> ${transformedKey}`);
  }
  
  // Try the transformed key in the URL
  let keyUrl = `https://hls-ck-container.classx.co.in/ck.cssa?k=${transformedKey}&edge-cache-token=${token}`;
  console.log(`[KEY] Trying key URL: ${keyUrl}`);
  
  const headers = { ...HEADERS };
  
  // Helper function to check if response is valid key
  const isValidKey = (keyBuffer) => {
    const keyText = keyBuffer.toString('utf8');
    // Ignore fake "Token expired" responses
    if (keyText.includes('expired') || keyText.includes('Token')) {
      return false;
    }
    // Check if it's a valid 16-byte key (binary data, not text)
    return keyBuffer.length === 16 || (keyBuffer.length > 0 && !keyText.match(/^[\x20-\x7E]+$/));
  };
  
  // Helper function to try a key URL
  const tryKeyUrl = async (url, description) => {
    try {
      console.log(`[KEY] Trying ${description}: ${url}`);
      const res = await fetch(url, { headers });
      console.log(`[FETCH] Response status: ${res.status}`);
      
      if (res.status === 200) {
        const keyBuffer = await res.arrayBuffer();
        const key = Buffer.from(keyBuffer);
        const keyText = key.toString('utf8');
        
        // Check if response is "Token expired" - this is a fake response, ignore it
        if (keyText.includes('expired') || keyText.includes('Token')) {
          console.warn(`[KEY] ⚠️  HLS container returned fake "Token expired" response (ignoring)`);
          return null;
        }
        
        console.log(`[KEY] ✅ Key downloaded successfully (${description})`);
        console.log(`[KEY] Key length: ${key.length} bytes`);
        console.log(`[KEY] Key hex: ${key.toString('hex')}`);
        
        if (key.length !== 16) {
          console.warn(`[KEY] ⚠️  WARNING: Expected 16 bytes, got ${key.length}`);
        }
        
        return key;
      } else {
        const errorText = await res.text();
        // Check if it says "Token expired" - this is a fake response, ignore it
        if (errorText.includes('expired') || errorText.includes('Token')) {
          console.warn(`[KEY] ⚠️  HLS container returned fake "Token expired" response (ignoring)`);
          return null;
        }
        console.warn(`[KEY] ${description} failed: ${res.status} - ${errorText.substring(0, 200)}`);
        return null;
      }
    } catch (err) {
      console.warn(`[KEY] ${description} error: ${err.message}`);
      return null;
    }
  };
  
  try {
    // Try pattern 1: ck.cssb with transformed key (from HAR analysis)
    let key = await tryKeyUrl(
      `https://hls-ck-container.classx.co.in/ck.cssb?k=${transformedKey}?edge-cache-token=${token}`,
      'pattern 1 (ck.cssb with transformed key)'
    );
    if (key) return key;
    
    // Try pattern 2: ck.cssa with transformed key
    key = await tryKeyUrl(
      `https://hls-ck-container.classx.co.in/ck.cssa?k=${transformedKey}&edge-cache-token=${token}`,
      'pattern 2 (ck.cssa with edge-cache-token)'
    );
    if (key) return key;
    
    // Try pattern 3: ck.cssb with edge-cache-token as query param
    key = await tryKeyUrl(
      `https://hls-ck-container.classx.co.in/ck.cssb?k=${transformedKey}&edge-cache-token=${token}`,
      'pattern 3 (ck.cssb with edge-cache-token as param)'
    );
    if (key) return key;
    
    // Try pattern 4: ck.cssa with alternative format
    key = await tryKeyUrl(
      `https://hls-ck-container.classx.co.in/ck.cssa?k=${transformedKey}?edge-cache-token=${token}`,
      'pattern 4 (ck.cssa alternative format)'
    );
    if (key) return key;
    
    // Try pattern 5: without edge-cache-token
    key = await tryKeyUrl(
      `https://hls-ck-container.classx.co.in/ck.cssb?k=${transformedKey}`,
      'pattern 5 (ck.cssb without token)'
    );
    if (key) return key;
    
    // Try pattern 4: with edge-cache-token in headers instead
    const headersWithToken = { ...headers, 'edge-cache-token': token };
    try {
      console.log(`[KEY] Trying pattern 4 (token in headers): https://hls-ck-container.classx.co.in/ck.cssa?k=${transformedKey}`);
      const res4 = await fetch(`https://hls-ck-container.classx.co.in/ck.cssa?k=${transformedKey}`, { headers: headersWithToken });
      console.log(`[FETCH] Response status: ${res4.status}`);
      
      if (res4.status === 200) {
        const keyBuffer4 = await res4.arrayBuffer();
        const key4 = Buffer.from(keyBuffer4);
        const keyText4 = key4.toString('utf8');
        
        if (!keyText4.includes('expired') && !keyText4.includes('Token')) {
          console.log(`[KEY] ✅ Key downloaded successfully (pattern 4)`);
          console.log(`[KEY] Key length: ${key4.length} bytes`);
          console.log(`[KEY] Key hex: ${key4.toString('hex')}`);
          if (key4.length === 16) {
            return key4;
          }
        } else {
          console.warn(`[KEY] ⚠️  HLS container returned fake "Token expired" response (ignoring)`);
        }
      }
    } catch (err) {
      console.warn(`[KEY] Pattern 4 error: ${err.message}`);
    }
    
    // Try pattern 5: Get key from segment base URL (HLS.js resolves key URI relative to playlist/segment base)
    // From HAR analysis: segment base URL is https://transcoded-videos.classx.co.in/videos/harkirat-data/511504-1759062548/hls-drm-a9230d/360p/
    // The key identifier in M3U8 is resolved relative to the base URL
    let baseUrlsToTry = [];
    
    // First, try segment base URL (where actual segments are) - this is most likely
    if (segmentBaseUrl) {
      baseUrlsToTry.push(segmentBaseUrl);
      console.log(`[KEY] Will try key at segment base URL: ${segmentBaseUrl}`);
    }
    
    // Try to construct segment base URLs from video data (pattern from HAR)
    if (!segmentBaseUrl && videoData && videoData.data) {
      const derivedPatterns = deriveSegmentBaseUrl(videoData);
      
      // Try to construct actual URLs by trying common hash patterns
      // The hash "a9230d" in HAR is 7 chars hex - might be derived from video data
      if (derivedPatterns && derivedPatterns.length > 0) {
        const data = videoData.data;
        const recDomain = data.rec_domain || 'harkirat.classx.co.in';
        const domainName = recDomain.split('.')[0];
        const videoId = data.id;
        const courseId = data.course_id;
        const strtotime = data.strtotime;
        
        // Try common hash patterns (short hex strings)
        const hashPatterns = [
          videoId ? videoId.substring(0, 7) : null,
          courseId ? courseId.substring(0, 7) : null,
          'a9230d', // From HAR
          'default',
          'master'
        ].filter(Boolean);
        
        for (const pattern of derivedPatterns) {
          if (pattern.includes('*')) {
            // Replace wildcard with hash patterns
            for (const hash of hashPatterns) {
              const actualUrl = pattern.replace('*/', `${hash}/`);
              // Extract quality from pattern or use default
              const qualityMatch = actualUrl.match(/\/(\d+p)\//);
              const quality = qualityMatch ? qualityMatch[1] : '360p';
              const baseUrl = actualUrl.replace(`/${quality}/`, '/');
              if (!baseUrlsToTry.includes(baseUrl)) {
                baseUrlsToTry.push(baseUrl);
                console.log(`[KEY] Constructed segment base URL: ${baseUrl}`);
              }
            }
          }
        }
      }
    }
    
    // Then try resolving key relative to M3U8 base URL (standard HLS behavior)
    if (m3u8Url) {
      const m3u8Base = m3u8Url.substring(0, m3u8Url.lastIndexOf('/') + 1);
      baseUrlsToTry.push(m3u8Base);
      console.log(`[KEY] Will try key at M3U8 base URL: ${m3u8Base}`);
    }
    
    // Try to construct segment base URL from video data (pattern from HAR) - legacy code
    if (!segmentBaseUrl && videoData && videoData.data) {
      // Try to construct from video data or common patterns
      if (videoData && videoData.data) {
        const courseId = videoData.data.course_id;
        const videoId = videoData.data.id;
        const recDomain = videoData.data.rec_domain || 'harkirat.classx.co.in';
        const domainName = recDomain.split('.')[0]; // e.g., "harkirat" from "harkirat.classx.co.in"
        
        // Try common patterns based on the user's example
        baseUrlsToTry.push(
          `https://transcoded-videos.classx.co.in/videos/${domainName}-data/${videoId}-${videoData.data.strtotime || ''}/hls-drm-*/360p`,
          `https://transcoded-videos.classx.co.in/videos/${domainName}-data/${courseId}-${videoId}/hls-drm-*/360p`,
          `https://transcoded-videos.classx.co.in/videos/${domainName}-data/${videoId}/hls-drm-*/360p`
        );
      }
      
      // Also try the M3U8 base URL pattern
      const m3u8Base = m3u8Url ? m3u8Url.substring(0, m3u8Url.lastIndexOf('/') + 1) : null;
      if (m3u8Base && m3u8Base.includes('appx-static')) {
        // Try transcoded-videos with similar path structure
        const pathMatch = m3u8Base.match(/\/testing-\d+\//);
        if (pathMatch) {
          baseUrlsToTry.push(`https://transcoded-videos.classx.co.in${pathMatch[0]}`);
        }
      }
    }
    
    for (const baseUrl of baseUrlsToTry) {
      // Skip wildcard patterns for now, or try to resolve them
      if (baseUrl.includes('*')) {
        console.log(`[KEY] Skipping wildcard pattern: ${baseUrl}`);
        continue;
      }
      
      console.log(`[KEY] Trying pattern 5 (transcoded-videos domain): Using segment base URL: ${baseUrl}`);
      
      // Try different key file patterns
      const keyFilePatterns = [
        `${keyIdentifier}.key`,
        `key-${keyIdentifier}`,
        `${transformedKey}.key`,
        `key-${transformedKey}`,
        `${keyIdentifier}`,
        `${transformedKey}`
      ];
      
      // Try key identifier directly (as HLS.js would resolve it)
      const keyUrlDirect = `${baseUrl}${keyIdentifier}`;
      console.log(`[KEY] Trying key URL (direct, as HLS.js would): ${keyUrlDirect}`);
      let key5 = await tryKeyUrl(keyUrlDirect, `pattern 5 direct (${baseUrl})`);
      if (key5) return key5;
      
      // Try with transformed key (from HAR: 1705855799 -> 5561f02e2048a11642632dbae2ca8be3)
      if (transformedKey !== keyIdentifier) {
        const keyUrlTransformed = `${baseUrl}${transformedKey}`;
        console.log(`[KEY] Trying key URL (transformed): ${keyUrlTransformed}`);
        key5 = await tryKeyUrl(keyUrlTransformed, `pattern 5 transformed (${baseUrl})`);
        if (key5) return key5;
        
        // Also try with .key extension
        const keyUrlTransformedExt = `${baseUrl}${transformedKey}.key`;
        console.log(`[KEY] Trying key URL (transformed with .key): ${keyUrlTransformedExt}`);
        key5 = await tryKeyUrl(keyUrlTransformedExt, `pattern 5 transformed .key (${baseUrl})`);
        if (key5) return key5;
      }
      
      // Try ck.cssb pattern at segment base URL (from HAR analysis)
      if (transformedKey !== keyIdentifier) {
        const keyUrlCssb = `${baseUrl}ck.cssb?k=${transformedKey}`;
        console.log(`[KEY] Trying ck.cssb pattern at segment base: ${keyUrlCssb}`);
        key5 = await tryKeyUrl(keyUrlCssb, `pattern 5 ck.cssb at base (${baseUrl})`);
        if (key5) return key5;
      }
      
      // Try different key file patterns
      for (const keyFile of keyFilePatterns) {
        try {
          const keyUrl5 = `${baseUrl}${keyFile}${token ? `?edge-cache-token=${token}` : ''}`;
          console.log(`[KEY] Trying key URL: ${keyUrl5}`);
          const res5 = await fetch(keyUrl5, { headers });
          console.log(`[FETCH] Response status: ${res5.status}`);
          
          if (res5.status === 200) {
            const keyBuffer5 = await res5.arrayBuffer();
            const key5 = Buffer.from(keyBuffer5);
            const keyText5 = key5.toString('utf8');
            
            if (!keyText5.includes('expired') && !keyText5.includes('Token') && !keyText5.includes('error') && !keyText5.includes('Error')) {
              console.log(`[KEY] ✅ Key downloaded successfully (pattern 5: ${keyFile})`);
              console.log(`[KEY] Key length: ${key5.length} bytes`);
              console.log(`[KEY] Key hex: ${key5.toString('hex')}`);
              if (key5.length === 16 || key5.length > 0) {
                return key5;
              }
            }
          }
        } catch (err) {
          // Continue to next pattern
        }
      }
      
      // Also try with edge-cache-token in headers
      for (const keyFile of keyFilePatterns) {
        try {
          const keyUrl5 = `${baseUrl}${keyFile}`;
          console.log(`[KEY] Trying key URL (with token in headers): ${keyUrl5}`);
          const res5 = await fetch(keyUrl5, { headers: headersWithToken });
          console.log(`[FETCH] Response status: ${res5.status}`);
          
          if (res5.status === 200) {
            const keyBuffer5 = await res5.arrayBuffer();
            const key5 = Buffer.from(keyBuffer5);
            const keyText5 = key5.toString('utf8');
            
            if (!keyText5.includes('expired') && !keyText5.includes('Token') && !keyText5.includes('error') && !keyText5.includes('Error')) {
              console.log(`[KEY] ✅ Key downloaded successfully (pattern 5 with headers: ${keyFile})`);
              console.log(`[KEY] Key length: ${key5.length} bytes`);
              console.log(`[KEY] Key hex: ${key5.toString('hex')}`);
              if (key5.length === 16 || key5.length > 0) {
                return key5;
              }
            }
          }
        } catch (err) {
          // Continue to next pattern
        }
      }
    }
    
    // If all methods failed, throw error
    throw new Error(`Unable to download key: HLS container returned fake "Token expired" response for all URL patterns. Key may need to be obtained through alternative methods (e.g., from encrypted_links).`);
  } catch (err) {
    console.error('[KEY] Error downloading key:', err);
    throw err;
  }
}

// Download a single segment
async function downloadSegment(segmentUrl, segmentIndex, totalSegments, token) {
  const headers = { ...HEADERS };
  if (token) {
    const urlObj = new URL(segmentUrl);
    if (!urlObj.searchParams.has('edge-cache-token')) {
      urlObj.searchParams.set('edge-cache-token', token);
      segmentUrl = urlObj.toString();
    }
  }
  
  try {
    console.log(`[SEGMENT ${segmentIndex}/${totalSegments}] Downloading: ${segmentUrl.substring(0, 80)}...`);
    const res = await fetch(segmentUrl, { headers });
    
    console.log(`[SEGMENT ${segmentIndex}/${totalSegments}] Response status: ${res.status}`);
    
    if (res.status !== 200) {
      const errorText = await res.text();
      throw new Error(`Failed to download segment: ${res.status} - ${errorText.substring(0, 100)}`);
    }
    
    // Check if segment has obfuscation extension (.tsa, .tsb, .tsc, .tsd, .tse)
    // These return text/base64, not binary
    const hasObfuscation = /\.(tsa|tsb|tsc|tsd|tse)(\?|$)/i.test(segmentUrl);
    
    let segment;
    if (hasObfuscation) {
      // Obfuscated segments are text/base64
      const text = await res.text();
      segment = Buffer.from(text, 'utf8');
      console.log(`[SEGMENT ${segmentIndex}/${totalSegments}] Downloaded ${segment.length} bytes (text/obfuscated)`);
    } else {
      // Standard segments are binary
      const segmentBuffer = await res.arrayBuffer();
      segment = Buffer.from(segmentBuffer);
      console.log(`[SEGMENT ${segmentIndex}/${totalSegments}] Downloaded ${segment.length} bytes (binary)`);
    }
    
    return segment;
  } catch (err) {
    console.error(`[SEGMENT ${segmentIndex}/${totalSegments}] Error:`, err.message);
    throw err;
  }
}

// Deobfuscation functions for different extensions (hls_tts_bypass method)
function decodeVideoTsa(inputString) {
  const shiftValue = 0xa * 0x2;  // 20 in decimal
  let result = '';
  
  for (let i = 0; i < inputString.length; i++) {
    const charCode = inputString.charCodeAt(i);
    const xorResult = charCode - shiftValue;
    result += String.fromCharCode(xorResult);
  }
  
  return Buffer.from(result, 'base64');
}

function decodeVideoTsb(inputString) {
  const xorValue = 0x3;   // 3 in decimal
  const shiftValue = 0x2a;  // 42 in decimal
  let result = '';
  
  for (let i = 0; i < inputString.length; i++) {
    const charCode = inputString.charCodeAt(i);
    const xorResult = charCode >> xorValue;  // Right shift by 3
    const shiftedResult = xorResult ^ shiftValue;  // XOR with 42
    result += String.fromCharCode(shiftedResult);
  }
  
  return Buffer.from(result, 'base64');
}

function decodeVideoTsc(inputString) {
  const shiftValue = 0xa;  // 10 in decimal
  let result = '';
  
  for (let i = 0; i < inputString.length; i++) {
    const charCode = inputString.charCodeAt(i);
    const xorResult = charCode - shiftValue;
    result += String.fromCharCode(xorResult);
  }
  
  return Buffer.from(result, 'base64');
}

function decodeVideoTsd(inputString) {
  const shiftValue = 0x2;  // 2 in decimal
  let result = '';
  
  for (let i = 0; i < inputString.length; i++) {
    const charCode = inputString.charCodeAt(i);
    const shiftedResult = charCode >> shiftValue;  // Right shift by 2
    result += String.fromCharCode(shiftedResult);
  }
  
  return Buffer.from(result, 'base64');
}

function decodeVideoTse(inputString) {
  const xorValue = 0x3;   // 3 in decimal
  const shiftValue = 0x2a;  // 42 in decimal
  let result = '';
  
  for (let i = 0; i < inputString.length; i++) {
    const charCode = inputString.charCodeAt(i);
    const xorResult = charCode ^ shiftValue;  // XOR with 42
    const shiftedResult = xorResult >> xorValue;  // Right shift by 3
    result += String.fromCharCode(shiftedResult);
  }
  
  return Buffer.from(result, 'base64');
}

// Remove first layer of obfuscation based on file extension
function removeObfuscation(segmentData, segmentUrl) {
  // Get file extension from URL
  const urlMatch = segmentUrl.match(/\.(tsa|tsb|tsc|tsd|tse)(\?|$)/i);
  const extension = urlMatch ? urlMatch[1].toLowerCase() : null;
  
  // If no obfuscation extension found, return as-is (might be standard .ts file)
  if (!extension) {
    console.log(`[DEOBFUSCATE] No obfuscation extension found, treating as standard encrypted segment`);
    return segmentData;
  }
  
  console.log(`[DEOBFUSCATE] Removing obfuscation for .${extension} extension`);
  
  // Convert segment to string if it's a buffer
  // Obfuscated segments are downloaded as text, so we need to handle them as strings
  let segmentStr;
  if (Buffer.isBuffer(segmentData)) {
    // If it's a buffer, convert to string (it should be UTF-8 text)
    segmentStr = segmentData.toString('utf8');
  } else if (typeof segmentData === 'string') {
    segmentStr = segmentData;
  } else {
    // Try to convert to string
    segmentStr = String(segmentData);
  }
  
  console.log(`[DEOBFUSCATE] Input length: ${segmentStr.length} chars, extension: .${extension}`);
  
  // Apply appropriate deobfuscation function (these expect string input)
  let deobfuscated;
  try {
    switch (extension) {
      case 'tsa':
        deobfuscated = decodeVideoTsa(segmentStr);
        break;
      case 'tsb':
        deobfuscated = decodeVideoTsb(segmentStr);
        break;
      case 'tsc':
        deobfuscated = decodeVideoTsc(segmentStr);
        break;
      case 'tsd':
        deobfuscated = decodeVideoTsd(segmentStr);
        break;
      case 'tse':
        deobfuscated = decodeVideoTse(segmentStr);
        break;
      default:
        console.warn(`[DEOBFUSCATE] Unknown extension .${extension}, returning as-is`);
        return segmentData;
    }
    
    console.log(`[DEOBFUSCATE] ✅ Deobfuscated ${segmentStr.length} chars -> ${deobfuscated.length} bytes`);
    return deobfuscated;
  } catch (err) {
    console.error(`[DEOBFUSCATE] Error in deobfuscation: ${err.message}`);
    throw new Error(`Failed to deobfuscate segment: ${err.message}`);
  }
}

// Decrypt segment using AES-128 (second layer after deobfuscation)
function decryptSegment(segment, key, iv, segmentUrl = null, segmentIndex = null) {
  try {
    // First, remove obfuscation if needed
    let segmentToDecrypt = segment;
    if (segmentUrl) {
      segmentToDecrypt = removeObfuscation(segment, segmentUrl);
      
      // After deobfuscation, the data should be binary (base64 decoded)
      // Verify it's valid binary data
      if (!Buffer.isBuffer(segmentToDecrypt)) {
        throw new Error('Deobfuscation did not return binary data');
      }
    }
    
    // Now decrypt with AES-128-CBC
    let ivBuffer;
    
    if (iv) {
      // Convert hex IV to buffer
      // IV format from M3U8: IV=0xa65c79d2237b4a594bc17047c7272f8b
      let ivHex = iv;
      if (typeof iv === 'string') {
        // Remove 0x prefix if present
        if (iv.startsWith('0x')) {
          ivHex = iv.slice(2);
        } else {
          ivHex = iv;
        }
        
        // Ensure it's exactly 32 hex characters (16 bytes)
        if (ivHex.length < 32) {
          // Pad with zeros on the left
          ivHex = ivHex.padStart(32, '0');
        } else if (ivHex.length > 32) {
          // Take last 32 characters
          ivHex = ivHex.slice(-32);
        }
        
        ivBuffer = Buffer.from(ivHex, 'hex');
      } else {
        ivBuffer = Buffer.from(iv);
      }
      
      // Ensure IV is exactly 16 bytes
      if (ivBuffer.length !== 16) {
        if (ivBuffer.length < 16) {
          // Pad with zeros on the left (big-endian)
          ivBuffer = Buffer.concat([Buffer.alloc(16 - ivBuffer.length, 0), ivBuffer]);
        } else {
          ivBuffer = ivBuffer.slice(0, 16);
        }
      }
      
      if (segmentIndex !== null) {
        console.log(`[DECRYPT] Segment ${segmentIndex + 1} IV: ${ivBuffer.toString('hex')}`);
      }
    } else {
      // Use zero IV if not provided
      ivBuffer = Buffer.alloc(16, 0);
      if (segmentIndex !== null) {
        console.warn(`[DECRYPT] No IV provided for segment ${segmentIndex + 1}, using zero IV`);
      }
    }
    
    // Ensure key is 16 bytes
    const keyBuffer = Buffer.isBuffer(key) ? key : Buffer.from(key);
    const aesKey = keyBuffer.length >= 16 ? keyBuffer.slice(0, 16) : Buffer.concat([keyBuffer, Buffer.alloc(16 - keyBuffer.length, 0)]);
    
    if (segmentIndex !== null) {
      console.log(`[DECRYPT] Segment ${segmentIndex + 1} Key: ${aesKey.toString('hex')}, IV: ${ivBuffer.toString('hex')}, Data length: ${segmentToDecrypt.length} bytes`);
    }
    
    // For AES-128-CBC, data must be a multiple of 16 bytes (block size)
    // If padding is enabled, it should handle this automatically
    const decipher = crypto.createDecipheriv('aes-128-cbc', aesKey, ivBuffer);
    decipher.setAutoPadding(true);
    
    const decrypted = Buffer.concat([
      decipher.update(segmentToDecrypt),
      decipher.final()
    ]);
    
    return decrypted;
  } catch (err) {
    if (segmentIndex !== null) {
      console.error(`[DECRYPT] Error decrypting segment ${segmentIndex + 1}:`, err.message);
      console.error(`[DECRYPT] Key: ${Buffer.isBuffer(key) ? key.toString('hex') : 'N/A'}`);
      console.error(`[DECRYPT] IV: ${iv || 'N/A'}`);
      console.error(`[DECRYPT] Segment length: ${segment.length} bytes`);
      if (segmentUrl) {
        console.error(`[DECRYPT] URL: ${segmentUrl}`);
      }
    } else {
      console.error('[DECRYPT] Error decrypting segment:', err);
    }
    throw err;
  }
}

// Download all segments and decrypt them
async function downloadAndDecryptSegments(segments, key, token) {
  console.log('\n========== STEP 7: Downloading and Decrypting Segments ==========');
  console.log(`[DOWNLOAD] Total segments: ${segments.length}`);
  console.log(`[DOWNLOAD] Using key: ${key.toString('hex')}`);
  
  const decryptedSegments = [];
  
  for (let i = 0; i < segments.length; i++) {
    try {
      console.log(`\n[DOWNLOAD] Processing segment ${i + 1}/${segments.length}`);
      
      // Download segment
      const encryptedSegment = await downloadSegment(segments[i].url, i + 1, segments.length, token);
      
      // Decrypt segment (with two-layer decryption support)
      console.log(`[DECRYPT] Decrypting segment ${i + 1}...`);
      // Use IV from segment's key info
      const segmentIV = segments[i].key?.iv;
      if (!segmentIV) {
        console.warn(`[DECRYPT] ⚠️  No IV found for segment ${i + 1}, using zero IV (this may cause decryption errors)`);
      }
      const decryptedSegment = decryptSegment(encryptedSegment, key, segmentIV, segments[i].url, i);
      console.log(`[DECRYPT] ✅ Decrypted segment ${i + 1}: ${encryptedSegment.length} bytes -> ${decryptedSegment.length} bytes`);
      
      decryptedSegments.push(decryptedSegment);
      
      // Progress update
      const progress = ((i + 1) / segments.length * 100).toFixed(1);
      console.log(`[PROGRESS] ${progress}% complete`);
      
    } catch (err) {
      console.error(`[ERROR] Failed to process segment ${i + 1}:`, err.message);
      // Continue with next segment
    }
  }
  
  console.log(`\n[DOWNLOAD] Successfully downloaded and decrypted ${decryptedSegments.length}/${segments.length} segments`);
  
  return decryptedSegments;
}

// Merge segments into MP4 file
function mergeToMP4(segments, outputPath) {
  console.log('\n========== STEP 8: Merging Segments to MP4 ==========');
  console.log(`[MERGE] Merging ${segments.length} segments to ${outputPath}`);
  
  try {
    const totalSize = segments.reduce((sum, seg) => sum + seg.length, 0);
    console.log(`[MERGE] Total size: ${(totalSize / 1024 / 1024).toFixed(2)} MB`);
    
    const merged = Buffer.concat(segments);
    fs.writeFileSync(outputPath, merged);
    
    console.log(`[MERGE] Successfully saved video to: ${outputPath}`);
    console.log(`[MERGE] File size: ${(merged.length / 1024 / 1024).toFixed(2)} MB`);
    
    return outputPath;
  } catch (err) {
    console.error('[MERGE] Error merging segments:', err);
    throw err;
  }
}

// Main function
async function main() {
  try {
    console.log('========================================');
    console.log('   VIDEO DOWNLOADER - STARTING');
    console.log('========================================\n');
    
    // Step 1: Fetch video details
    const videoData = await fetchVideoDetails();
    
    // Step 2: Extract token and player URL
    const { token, playerUrl } = extractVideoInfo(videoData);
    
    // Step 3: Load player page and extract encrypted data (hls_tts_bypass method)
    const { html, encryptedData, m3u8Url, edgeCacheToken, segmentBaseUrl } = await loadPlayerPageAndExtractInfo(playerUrl, token);
    
    let playlist;
    let finalToken = token;
    
    // Try hls_tts_bypass method first
    if (encryptedData && encryptedData.kstr && encryptedData.jstr) {
      console.log(`[MAIN] Using hls_tts_bypass method (decrypting from HTML)`);
      finalToken = encryptedData.token || token;
      
      // Step 4: Decrypt M3U8 from jstr (hls_tts_bypass method)
      playlist = await decryptM3U8FromJstr(encryptedData, finalToken);
    } else {
      // Fallback to original method
      console.log(`[MAIN] Using fallback method (direct M3U8 download)`);
      
      if (!m3u8Url) {
        throw new Error('Could not find M3U8 URL in player page and encrypted data extraction failed');
      }
      
      // Step 4: Download M3U8 playlist (fallback method)
      playlist = await downloadM3U8(m3u8Url, edgeCacheToken || token);
    }
    
    // Step 5: Parse M3U8
    // Extract base URL from first segment if available, or use M3U8 URL base
    const firstSegmentMatch = playlist.match(/https?:\/\/[^\s]+/);
    let m3u8BaseUrl = '';
    if (firstSegmentMatch) {
      m3u8BaseUrl = firstSegmentMatch[0].substring(0, firstSegmentMatch[0].lastIndexOf('/') + 1);
    } else if (m3u8Url) {
      m3u8BaseUrl = m3u8Url.substring(0, m3u8Url.lastIndexOf('/') + 1);
    }
    const { segments, keyInfo, actualSegmentBaseUrl } = parseM3U8(playlist, m3u8BaseUrl || m3u8Url || '');
    
    if (segments.length === 0) {
      throw new Error('No segments found in M3U8 playlist');
    }
    
    // Use actual segment base URL if found
    let finalSegmentBaseUrl = actualSegmentBaseUrl || segmentBaseUrl;
    if (actualSegmentBaseUrl) {
      console.log(`[MAIN] Using segment base URL from M3U8: ${actualSegmentBaseUrl}`);
    }
    
    // Step 6: Get decryption key
    let key = null;
    
    // Try hls_tts_bypass method first if we have encrypted data
    if (encryptedData && encryptedData.kstr) {
      try {
        console.log(`[MAIN] Decrypting key from kstr using hls_tts_bypass method...`);
        key = await decryptKeyFromKstr(encryptedData, finalToken);
        console.log(`[MAIN] ✅ Successfully decrypted key from kstr`);
        console.log(`[MAIN] Key hex: ${key.toString('hex')}`);
      } catch (err) {
        console.warn(`[MAIN] ⚠️  Failed to decrypt key from kstr: ${err.message}`);
        console.log(`[MAIN] Falling back to alternative key extraction methods...`);
        key = null; // Reset to try fallback methods
      }
    }
    
    // If hls_tts_bypass method didn't work or wasn't available, try fallback methods
    if (!key) {
      // Fallback: Try VideoJS extraction
      try {
        console.log(`[MAIN] Attempting to extract keys from videojs player...`);
        const videojsResult = await extractKeysFromVideojs(playerUrl, edgeCacheToken || finalToken);
        key = videojsResult.key;
        console.log(`[MAIN] ✅ Successfully extracted key from videojs`);
      } catch (err2) {
        console.warn(`[MAIN] ⚠️  VideoJS extraction also failed: ${err2.message}`);
        
        // Final fallback: Try manual key download (if keyInfo.url exists)
        if (keyInfo && keyInfo.url) {
          console.log(`[MAIN] Trying manual key download method...`);
          const m3u8BaseUrl = m3u8Url ? m3u8Url.substring(0, m3u8Url.lastIndexOf('/') + 1) : '';
          key = await downloadKey(keyInfo.url, edgeCacheToken || finalToken, videoData, finalSegmentBaseUrl, m3u8BaseUrl);
        } else {
          throw new Error('All key extraction methods failed. Cannot proceed without decryption key.');
        }
      }
    }
    
    // Step 7: Download and decrypt all segments
    const decryptedSegments = await downloadAndDecryptSegments(segments, key, edgeCacheToken);
    
    if (decryptedSegments.length === 0) {
      throw new Error('No segments were successfully downloaded');
    }
    
    // Step 8: Merge to MP4
    const outputPath = 'video_downloaded.mp4';
    mergeToMP4(decryptedSegments, outputPath);
    
    console.log('\n========================================');
    console.log('   VIDEO DOWNLOADER - COMPLETE!');
    console.log('========================================');
    console.log(`\nVideo saved to: ${outputPath}`);
    
  } catch (err) {
    console.error('\n========================================');
    console.error('   VIDEO DOWNLOADER - ERROR');
    console.error('========================================');
    console.error('Error:', err.message);
    console.error('Stack:', err.stack);
    process.exit(1);
  }
}

// Run the script
main();
