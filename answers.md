# Prototype Pollution Lab - Answer Key

## Challenge 1: Identify the Vulnerability

### Vulnerable Code:
```javascript
function processConfig(defaultConfig, userConfig) {
    function recursiveMerge(target, source) {
        for (const key in source) {
            if (typeof source[key] === 'object' && source[key] !== null) {
                if (!target[key]) target[key] = {};
                recursiveMerge(target[key], source[key]);
            } else {
                target[key] = source[key];
            }
        }
    }
    
    const finalConfig = {};
    recursiveMerge(finalConfig, defaultConfig);
    recursiveMerge(finalConfig, userConfig);  // userConfig comes from user input
    
    return finalConfig;
}

// App uses the config
if (config.features.advanced) {
    enableAdvancedFeatures();
}
```

### Vulnerability Analysis:
The `recursiveMerge` function is vulnerable to prototype pollution because:
1. It performs no validation on the keys in the source object
2. It doesn't check if properties actually belong to the source object (using hasOwnProperty)
3. It doesn't use a prototypeless object as the base

### Attack Vector:
An attacker could send a payload like:
```javascript
const maliciousConfig = {
    "__proto__": {
        "features": {
            "advanced": true
        }
    }
};
```

This would cause all objects (including the empty object at `config.features`) to have an `advanced` property set to `true`, potentially enabling features the user shouldn't have access to.

### Secure Implementation:
```javascript
function processConfig(defaultConfig, userConfig) {
    function safeMerge(target, source) {
        // Skip __proto__ and constructor
        for (const key in source) {
            if (key === '__proto__' || key === 'constructor') continue;
            
            // Ensure property belongs to source object
            if (Object.prototype.hasOwnProperty.call(source, key)) {
                if (typeof source[key] === 'object' && source[key] !== null) {
                    if (!target[key]) target[key] = {};
                    safeMerge(target[key], source[key]);
                } else {
                    target[key] = source[key];
                }
            }
        }
        return target;
    }
    
    // Use Object.create(null) for a prototypeless object
    const finalConfig = Object.create(null);
    safeMerge(finalConfig, defaultConfig);
    safeMerge(finalConfig, userConfig);
    
    return finalConfig;
}
```

## Challenge 2: Fix the Vulnerability

### Vulnerable Code:
```javascript
function parseQueryParams(url) {
    const params = {};
    const queryString = url.split('?')[1] || '';
    const pairs = queryString.split('&');
    
    for (const pair of pairs) {
        if (!pair) continue;
        
        const [key, value] = pair.split('=').map(decodeURIComponent);
        
        // Support nested parameters with dot notation
        if (key.includes('.')) {
            const parts = key.split('.');
            let current = params;
            
            for (let i = 0; i < parts.length - 1; i++) {
                const part = parts[i];
                if (!current[part]) current[part] = {};
                current = current[part];
            }
            
            current[parts[parts.length - 1]] = value;
        } else {
            params[key] = value;
        }
    }
    
    return params;
}
```

### Vulnerability Analysis:
This function is vulnerable to prototype pollution because:
1. It doesn't check for dangerous keys like `__proto__` or `constructor`
2. When processing nested parameters with dot notation, it doesn't validate the key parts
3. It uses a regular object (`{}`) rather than a prototypeless object as the base

### Attack Vector:
An attacker could craft a URL like:
```
https://example.com?__proto__.isAdmin=true
```

Or with nested keys:
```
https://example.com?__proto__.features.admin=true
```

### Secure Implementation:
```javascript
function parseQueryParams(url) {
    // Use Object.create(null) for a prototype-less object
    const params = Object.create(null);
    const queryString = url.split('?')[1] || '';
    const pairs = queryString.split('&');
    
    for (const pair of pairs) {
        if (!pair) continue;
        
        const [key, value] = pair.split('=').map(decodeURIComponent);
        
        // Skip dangerous properties
        if (key === '__proto__' || key === 'constructor') continue;
        
        // Support nested parameters with dot notation
        if (key.includes('.')) {
            const parts = key.split('.');
            
            // Skip if any part is __proto__ or constructor
            if (parts.includes('__proto__') || parts.includes('constructor')) continue;
            
            let current = params;
            
            for (let i = 0; i < parts.length - 1; i++) {
                const part = parts[i];
                if (!Object.prototype.hasOwnProperty.call(current, part)) {
                    current[part] = Object.create(null); // Use prototypeless objects
                }
                current = current[part];
            }
            
            current[parts[parts.length - 1]] = value;
        } else {
            params[key] = value;
        }
    }
    
    return params;
}
```

## Final Challenge: Real-world Application

### Vulnerable Code:
```javascript
const express = require('express');
const app = express();
app.use(express.json());

// Global application settings
const appSettings = {
    features: {
        admin: false,
        experimental: false
    },
    security: {
        requireMFA: true
    }
};

// Process user settings and merge with defaults
app.post('/api/settings', (req, res) => {
    const userSettings = req.body;
    
    // Update settings with user preferences
    function updateSettings(base, updates) {
        for (const key in updates) {
            if (typeof updates[key] === 'object') {
                if (!base[key]) base[key] = {};
                updateSettings(base[key], updates[key]);
            } else {
                base[key] = updates[key];
            }
        }
    }
    
    // Apply user settings to app settings
    updateSettings(appSettings, userSettings);
    
    // Check user access level
    if (appSettings.features.admin) {
        res.json({ 
            message: "Admin settings applied",
            settings: appSettings
        });
    } else {
        res.json({ 
            message: "User settings applied",
            settings: filterSensitiveData(appSettings)
        });
    }
});

function filterSensitiveData(data) {
    // Remove sensitive data before sending to user
    const filtered = JSON.parse(JSON.stringify(data));
    delete filtered.security;
    return filtered;
}

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
```

### Vulnerability Analysis:
This application has several severe prototype pollution vulnerabilities:

1. **Vulnerable `updateSettings` function:**
   - No validation of keys in the `updates` object
   - Directly modifies the `base` object
   - No protection against `__proto__` or `constructor` properties

2. **Global Mutable State:**
   - The `appSettings` object is shared across all requests
   - Changes made by one user affect all users

3. **Privilege Escalation:**
   - The code checks `appSettings.features.admin` to determine if a user is an admin
   - This can be polluted via prototype pollution to gain admin access

4. **Inadequate Input Validation:**
   - No validation of the user input structure before processing

### Attack Vector:
An attacker could send a POST request to `/api/settings` with:
```json
{
  "__proto__": {
    "features": {
      "admin": true
    }
  }
}
```

This would pollute the Object prototype, granting admin privileges to all users of the application.

### Secure Implementation:
```javascript
const express = require('express');
const app = express();
app.use(express.json());

// Global application settings - use Object.freeze for immutability
const appSettings = Object.freeze({
    features: Object.freeze({
        admin: false,
        experimental: false
    }),
    security: Object.freeze({
        requireMFA: true
    })
});

// Process user settings and merge with defaults
app.post('/api/settings', (req, res) => {
    const userSettings = req.body;
    
    // Create a fresh copy of settings for this request
    // Using structured clone or deep copy to avoid reference issues
    const currentSettings = structuredClone(appSettings);
    // Alternative: const currentSettings = JSON.parse(JSON.stringify(appSettings));
    
    try {
        // Apply user settings safely
        const updatedSettings = safeUpdateSettings(currentSettings, userSettings);
        
        // Check user access level - get from authentication, not from settings
        const isAdmin = isUserActuallyAdmin(req);
        
        if (isAdmin) {
            res.json({ 
                message: "Admin settings applied",
                settings: updatedSettings
            });
        } else {
            // If admin status was changed via settings but user is not actually admin
            if (updatedSettings.features.admin && !isAdmin) {
                // Log potential attack attempt
                console.warn("Potential privilege escalation attempt", req.ip);
                // Reset admin status
                updatedSettings.features.admin = false;
            }
            
            res.json({ 
                message: "User settings applied",
                settings: filterSensitiveData(updatedSettings)
            });
        }
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Safe update function that prevents prototype pollution
function safeUpdateSettings(base, updates) {
    // Create a new object with no prototype
    const result = Object.create(null);
    
    // First copy all original properties
    for (const key in base) {
        if (Object.prototype.hasOwnProperty.call(base, key)) {
            if (typeof base[key] === 'object' && base[key] !== null) {
                result[key] = safeUpdateSettings(base[key], {});
            } else {
                result[key] = base[key];
            }
        }
    }
    
    // Then apply updates safely
    for (const key in updates) {
        // Skip dangerous properties
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;
        }
        
        // Ensure property belongs to the updates object
        if (Object.prototype.hasOwnProperty.call(updates, key)) {
            if (typeof updates[key] === 'object' && updates[key] !== null) {
                // For objects, recursively update
                if (typeof result[key] === 'object' && result[key] !== null) {
                    result[key] = safeUpdateSettings(result[key], updates[key]);
                } else {
                    // If not an object in the base, create a new object
                    result[key] = safeUpdateSettings({}, updates[key]);
                }
            } else {
                // For primitive values, simply copy
                result[key] = updates[key];
            }
        }
    }
    
    return result;
}

function filterSensitiveData(data) {
    // Create a new object with no prototype
    const filtered = Object.create(null);
    
    // Safely copy non-sensitive data
    for (const key in data) {
        if (Object.prototype.hasOwnProperty.call(data, key) && key !== 'security') {
            if (typeof data[key] === 'object' && data[key] !== null) {
                filtered[key] = filterSensitiveData(data[key]);
            } else {
                filtered[key] = data[key];
            }
        }
    }
    
    return filtered;
}

// Authorization check - get from authentication, not from settings
function isUserActuallyAdmin(req) {
    // In a real app, this would validate the user's auth token
    // against a database or auth service
    return req.headers['x-admin-token'] === 'valid-admin-token';
}

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
```

## Key Security Improvements:

1. **Immutable Default Settings:**
   - Using `Object.freeze()` to prevent modification of the default settings

2. **Per-Request Settings Copy:**
   - Creating a deep copy of settings for each request prevents cross-request pollution
   - Using `structuredClone()` for deep copying (or `JSON.parse(JSON.stringify())` for older environments)

3. **Safe Update Function:**
   - Using `Object.create(null)` for prototypeless objects
   - Explicitly checking for and rejecting dangerous properties (`__proto__`, `constructor`, `prototype`)
   - Using `Object.prototype.hasOwnProperty.call()` to safely check property ownership
   - Creating new objects instead of modifying existing ones

4. **Proper Authorization Check:**
   - Getting admin status from authentication, not from user-controlled settings
   - Detecting potential privilege escalation attempts

5. **Safe Data Filtering:**
   - Using prototypeless objects when filtering sensitive data
   - Employing proper error handling

6. **Input Validation:**
   - Using try-catch to handle potential errors during settings processing
   - Returning appropriate HTTP status codes

## Common Prototype Pollution Patterns to Watch For:

1. **Object Merging Functions:**
   ```javascript
   function merge(target, source) {
       for (let key in source) {
           if (typeof source[key] === 'object') {
               if (!target[key]) target[key] = {};
               merge(target[key], source[key]);
           } else {
               target[key] = source[key];
           }
       }
   }
   ```

2. **Dynamic Property Access:**
   ```javascript
   function setProperty(obj, path, value) {
       const parts = path.split('.');
       let current = obj;
       
       for (let i = 0; i < parts.length - 1; i++) {
           const part = parts[i];
           if (!current[part]) current[part] = {};
           current = current[part];
       }
       
       current[parts[parts.length - 1]] = value;
   }
   ```

3. **Cloning Without Validation:**
   ```javascript
   function clone(obj) {
       if (typeof obj !== 'object' || obj === null) return obj;
       const copy = Array.isArray(obj) ? [] : {};
       
       for (const key in obj) {
           copy[key] = clone(obj[key]);
       }
       
       return copy;
   }
   ```

4. **Default Options Merging:**
   ```javascript
   function createWithDefaults(options) {
       const defaults = { debug: false, timeout: 1000 };
       
       for (const key in options) {
           defaults[key] = options[key];
       }
       
       return defaults;
   }
   ```

## Protection Checklist:

1. ✅ Use `Object.create(null)` to create objects without prototype
2. ✅ Check for and reject dangerous property names like `__proto__` and `constructor`
3. ✅ Use `Object.prototype.hasOwnProperty.call(obj, prop)` for property checks
4. ✅ Use `Object.freeze()` for immutable configuration objects
5. ✅ Prefer `Object.assign({}, obj)` or spread operators (`{...obj}`) over direct property copying
6. ✅ Implement JSON Schema validation for user input
7. ✅ Create deep copies of objects instead of modifying them directly
8. ✅ Consider using libraries like lodash's `_.cloneDeep()` with security patches applied
9. ✅ Keep dependencies updated with security patches
10. ✅ Don't rely on object properties for critical security decisions

## Real-world Examples:

1. **CVE-2019-10744 (lodash):**
   - Affected lodash versions < 4.17.12
   - Functions like `_.merge`, `_.mergeWith`, etc. were vulnerable
   - Fixed by adding checks for `__proto__` keys

2. **CVE-2020-28498 (axios):**
   - Vulnerable when merging user-supplied configs
   - Attack via nested objects containing `__proto__` keys
   - Fixed in axios 0.21.1

3. **jQuery $.extend():**
   - Fixed in jQuery 3.4.0
   - The deep extend functionality was vulnerable

4. **Hoek (Node.js library):**
   - CVE-2018-3728
   - Fixed in version 5.0.3/4.2.1/etc.
   - Used by many npm packages

## Detection Methods:

1. **Static Analysis Tools:**
   - ESLint with security plugins
   - SonarQube with JavaScript security rules
   - NodeJsScan

2. **Dynamic Testing:**
   - Create test cases with payloads containing `__proto__` properties
   - Check if Object prototype is polluted after function execution:
   ```javascript
   const emptyObj = {};
   console.log(emptyObj.polluted); // Should be undefined
   ```

3. **Code Review Red Flags:**
   - Recursive property copying without validation
   - Dynamic property access via string paths
   - Direct modification of object properties from user input
   - Lack of input validation before property assignment