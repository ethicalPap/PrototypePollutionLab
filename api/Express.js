const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const app = express();
const port = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Store computer objects (normally this would be a database)
const computers = {
  "computer1": {
    id: "computer1",
    brand: "Lenovo",
    model: "ThinkPad T14",
    color: "Black",
    weight: "1.5kg/3.3lbs",
    powered: false,
    wifiConnected: false
  }
};

// VULNERABLE: Recursive function that sets values by path - similar to the frontend
function setValueByPath(obj, path, value) {
  // Handle values like __proto__.toString or constructor.prototype
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
  
  // Try to interpret values
  if (value === 'true') value = true;
  else if (value === 'false') value = false;
  else if (!isNaN(value)) value = Number(value);
  else {
    try {
      // Attempt to parse as JSON
      if ((value.startsWith('{') && value.endsWith('}')) || 
          (value.startsWith('[') && value.endsWith(']'))) {
        value = JSON.parse(value);
      }
    } catch (e) {
      // Keep as string if parsing fails
    }
  }
  
  current[lastKey] = value;
}

// VULNERABLE: This endpoint allows updating computer properties without proper sanitization
app.post('/api/computers/:id/update', (req, res) => {
  const computerId = req.params.id;
  const updates = req.body;
  
  // Check if computer exists
  if (!computers[computerId]) {
    return res.status(404).json({ error: "Computer not found" });
  }
  
  // Apply all updates from the request body - VULNERABLE to prototype pollution
  for (const [key, value] of Object.entries(updates)) {
    setValueByPath(computers[computerId], key, value);
  }
  
  // Power ON/OFF functionality that uses potentially polluted methods
  if (updates.powered === true && computers[computerId].onPowerOn) {
    console.log("Executing onPowerOn action");
    // In a real scenario, this could execute polluted code
    console.log(computers[computerId].onPowerOn);
  }
  
  // WiFi connection that uses potentially polluted callbacks
  if (updates.wifiConnected === true && computers[computerId].wifiCallback) {
    console.log("Executing wifiCallback");
    // In a real scenario, this could execute polluted code
    console.log(computers[computerId].wifiCallback);
  }
  
  return res.json(computers[computerId]);
});

// Get a specific computer
app.get('/api/computers/:id', (req, res) => {
  const computerId = req.params.id;
  
  if (!computers[computerId]) {
    return res.status(404).json({ error: "Computer not found" });
  }
  
  return res.json(computers[computerId]);
});

// Get all computers
app.get('/api/computers', (req, res) => {
  return res.json(computers);
});

// Serve the index.html file from public directory
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Add a route to test if prototype pollution worked
app.get('/api/test-pollution', (req, res) => {
  // Create a new object to check if its prototype is polluted
  const testObj = {};
  
  // Check if any common prototype methods are polluted
  const pollutionTests = {
    toString: typeof testObj.toString === 'function' ? 
              testObj.toString.toString().includes('native code') ? 'Not polluted' : 'POLLUTED!' : 'Missing',
    hasOwnProperty: typeof testObj.hasOwnProperty === 'function' ? 
                   testObj.hasOwnProperty.toString().includes('native code') ? 'Not polluted' : 'POLLUTED!' : 'Missing',
    isPrototypeOf: typeof testObj.isPrototypeOf === 'function' ? 
                  testObj.isPrototypeOf.toString().includes('native code') ? 'Not polluted' : 'POLLUTED!' : 'Missing'
  };
  
  // Return the test results and a new empty object to see if it has polluted properties
  return res.json({
    pollutionTests,
    newEmptyObject: {},
    message: "Check if the 'newEmptyObject' has unexpected properties added to it from pollution"
  });
});

app.listen(port, () => {
  console.log(`Prototype pollution demo server running at http://localhost:${port}`);
});