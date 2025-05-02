# Prototype Pollution API Demo

This project demonstrates a prototype pollution vulnerability in a simple API backend. It shows how a vulnerable API endpoint can be exploited to cause prototype pollution, potentially leading to security issues like XSS attacks.

## Security Warning

**This is a deliberately vulnerable application for educational purposes only.**

- Do not deploy this in a production environment
- Run this only on a local development machine
- Do not expose this to the internet
- Use this only for learning about prototype pollution vulnerabilities

## Setup Instructions

1. Clone this repository
2. Install dependencies

```bash
npm install express body-parser cors
```

3. Create the file structure:

```
prototype-pollution-demo/
├── server.js         # The API backend
├── public/
│   └── index.html    # The frontend interface
└── README.md         # This file
```

4. Copy the server.js code to your server.js file
5. Copy the index.html code to public/index.html
6. Start the server:

```bash
node server.js
```

7. Visit http://localhost:3000 in your browser

## How to Demonstrate Prototype Pollution

1. The web interface provides a form to send JSON updates to the API
2. Exploit the vulnerability by sending payloads like:

```json
{
  "__proto__": {
    "toString": "alert('Prototype polluted!')"
  }
}
```

3. Click the "Test Pollution" button to verify if the pollution worked
4. Try other prototype pollution techniques shown in the examples

## Explanation of the Vulnerability

The vulnerability exists in the `setValueByPath` function in the API, which allows setting arbitrary properties on objects without properly sanitizing paths. When it encounters a path like `__proto__.toString`, it will set properties on the object prototype, affecting all objects in the application.

### Key vulnerable code:

```javascript
// VULNERABLE: This endpoint allows updating computer properties without proper sanitization
app.post('/api/computers/:id/update', (req, res) => {
  const updates = req.body;
  
  // Apply all updates from the request body - VULNERABLE to prototype pollution
  for (const [key, value] of Object.entries(updates)) {
    setValueByPath(computers[computerId], key, value);
  }
  
  // ...
});
```

### The vulnerable `setValueByPath` function:

```javascript
function setValueByPath(obj, path, value) {
  const parts = path.split('.');
  let current = obj;
  
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i];
    if (!current[key] || typeof current[key] !== 'object') {
      current[key] = {};
    }
    current = current[key];
  }
  
  // Set the final property
  const lastKey = parts[parts.length - 1];
  current[lastKey] = value;
}
```

## Prevention Measures

To fix this vulnerability, you should:

1. Blacklist dangerous properties like `__proto__`, `constructor`, and `prototype`
2. Use Object.create(null) to create objects without a prototype
3. Use Object.defineProperty() instead of direct assignment
4. Use a library like lodash.set with a patched version that prevents prototype pollution

## Example Fix

```javascript
function safeSetValueByPath(obj, path, value) {
  // Reject dangerous property access
  if (path.includes('__proto__') || path.includes('constructor') || path.includes('prototype')) {
    console.log('Dangerous property access attempt:', path);
    return;
  }
  
  const parts = path.split('.');
  let current = obj;
  
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i];
    
    // Skip if trying to modify an object's prototype
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      return;
    }
    
    if (!current[key] || typeof current[key] !== 'object') {
      current[key] = Object.create(null); // Create object with no prototype
    }
    current = current[key];
  }
  
  const lastKey = parts[parts.length - 1];
  
  // Skip if trying to modify a dangerous property
  if (lastKey === '__proto__' || lastKey === 'constructor' || lastKey === 'prototype') {
    return;
  }
  
  // Use defineProperty for safer assignment
  Object.defineProperty(current, lastKey, {
    value: value,
    writable: true,
    enumerable: true,
    configurable: true
  });
}
```

## Resources for Learning More About Prototype Pollution

- [OWASP - Prototype Pollution](https://owasp.org/www-community/vulnerabilities/Prototype_Pollution)
- [Snyk - Prototype Pollution Attack](https://snyk.io/blog/after-three-years-of-silence-a-new-jquery-prototype-pollution-vulnerability-emerges-once-again/)
- [HackTricks - Prototype Pollution](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution)
- [PortSwigger - DOM Prototype Pollution](https://portswigger.net/web-security/dom-based/prototype-pollution)