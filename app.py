import streamlit as st
import json
import html
import random
from dataclasses import dataclass
from typing import Dict, List, Any

# Configure page
st.set_page_config(
    page_title="Prototype Pollution Lab",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Set up styling
st.markdown("""
<style>
.vuln-box {
    padding: 20px;
    border-radius: 5px;
    margin-bottom: 20px;
}
.success-box {
    background-color: #d1e7dd;
    border: 1px solid #badbcc;
}
.danger-box {
    background-color: #f8d7da;
    border: 1px solid #f5c2c7;
}
.code-output {
    background-color: #f8f9fa;
    border: 1px solid #dee2e6;
    border-radius: 5px;
    padding: 15px;
    font-family: monospace;
    white-space: pre;
}
</style>
""", unsafe_allow_html=True)

# Helper Functions 

def render_code_block(code, language="javascript"):
    """Render formatted code block"""
    return f"""```{language}
{code}
```"""

def display_vulnerability_scenario(title, code_sample, description, exploitation=None):
    """Display a vulnerability scenario with code and explanation"""
    st.subheader(title)
    st.write(description)
    st.code(code_sample, language="javascript")
    
    if exploitation:
        with st.expander("Show Exploitation Example"):
            st.write(exploitation["description"])
            st.code(exploitation["code"], language="javascript")

# Vulnerable Code Examples

VULNERABLE_MERGE_FUNCTION = """
function mergeObjects(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            mergeObjects(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Usage example
const userPreferences = {};
const userInput = JSON.parse(userProvidedData);  // Untrusted input
mergeObjects(userPreferences, userInput);
"""

VULNERABLE_JSON_PARSE = """
function parseAndProcess(jsonString) {
    const data = JSON.parse(jsonString);
    const config = {};
    
    // Copy properties from data to config
    for (const key in data) {
        config[key] = data[key];
    }
    
    return config;
}

// Example usage with user input
const userInput = '{"__proto__": {"isAdmin": true}}';
const config = parseAndProcess(userInput);
console.log(({}).isAdmin);  // Will output: true
"""

VULNERABLE_QUERY_PARSER = """
function parseQuery(queryString) {
    const params = {};
    const pairs = queryString.split('&');
    
    for (let i = 0; i < pairs.length; i++) {
        const [key, value] = pairs[i].split('=');
        
        // Vulnerable deep property setter
        setProperty(params, key, value);
    }
    
    return params;
}

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

// Example:
// If queryString is "__proto__.toString=alert(1)"
// Every object's toString method would be replaced!
"""

# Safe Code Examples

SAFE_MERGE_FUNCTION = """
function safeMergeObjects(target, source) {
    // Create a shallow copy first
    const result = Object.assign({}, target);
    
    for (const key in source) {
        // Skip __proto__ and constructor
        if (key === '__proto__' || key === 'constructor') continue;
        
        // Check if property actually belongs to source
        if (Object.prototype.hasOwnProperty.call(source, key)) {
            if (typeof source[key] === 'object' && source[key] !== null) {
                result[key] = safeMergeObjects(result[key] || {}, source[key]);
            } else {
                result[key] = source[key];
            }
        }
    }
    
    return result;
}
"""

SAFE_JSON_PARSE = """
function safeJSONParse(jsonString) {
    // Use JSON.parse with a reviver function
    return JSON.parse(jsonString, (key, value) => {
        // Reject __proto__ and constructor keys
        if (key === '__proto__' || key === 'constructor') {
            return undefined;
        }
        return value;
    });
}

// Or better yet, use Object.create(null) for "prototypeless" objects
function parseAndProcessSafely(jsonString) {
    const data = JSON.parse(jsonString);
    // Create a prototypeless object
    const config = Object.create(null);
    
    // Copy properties safely
    for (const key in data) {
        if (Object.prototype.hasOwnProperty.call(data, key) && 
            key !== '__proto__' && key !== 'constructor') {
            config[key] = data[key];
        }
    }
    
    return config;
}
"""

SAFE_QUERY_PARSER = """
function safeParseQuery(queryString) {
    const params = {};
    const pairs = queryString.split('&');
    
    for (let i = 0; i < pairs.length; i++) {
        const [key, value] = pairs[i].split('=');
        
        // Check for dangerous property names
        if (key === '__proto__' || key === 'constructor') continue;
        
        // Use safe property setter
        safeSetProperty(params, key, value);
    }
    
    return params;
}

function safeSetProperty(obj, path, value) {
    const parts = path.split('.');
    
    // Reject paths containing __proto__ or constructor
    if (parts.includes('__proto__') || parts.includes('constructor')) {
        return;
    }
    
    let current = obj;
    
    for (let i = 0; i < parts.length - 1; i++) {
        const part = parts[i];
        if (!Object.prototype.hasOwnProperty.call(current, part)) {
            current[part] = {};
        }
        current = current[part];
    }
    
    current[parts[parts.length - 1]] = value;
}
"""

# Main Application

st.title("Prototype Pollution Lab")
st.write("""
This interactive lab demonstrates JavaScript prototype pollution vulnerabilities and how to prevent them.
Prototype pollution occurs when an attacker is able to modify a JavaScript object's prototype (e.g., `Object.prototype`),
potentially leading to severe security issues.
""")

# Sidebar navigation
lab_option = st.sidebar.radio(
    "Select Lab Section",
    ["Introduction to Prototype Pollution", 
     "Interactive Playground", 
     "Real-world Examples",
     "Prevention Techniques",
     "Challenge Lab"]
)

if lab_option == "Introduction to Prototype Pollution":
    st.header("Introduction to Prototype Pollution")
    
    st.write("""
    ### What is Prototype Pollution?
    
    Prototype pollution is a vulnerability that occurs when an attacker is able to manipulate 
    JavaScript's prototype-based inheritance mechanism by injecting properties into an object's prototype.
    
    In JavaScript, all objects inherit properties from their prototype. When a property is accessed on an object,
    JavaScript first looks for that property on the object itself. If it's not found, JavaScript looks up the prototype chain.
    
    ### The Basics of JavaScript Prototypes
    """)
    
    with st.expander("JavaScript Prototype Refresher"):
        st.write("""
        Every JavaScript object has a link to a prototype object. When trying to access a property that does not exist 
        in an object, JavaScript tries to find the property in the object's prototype, and so on.
        
        The most common way to access an object's prototype is through the `__proto__` property.
        """)
        
        st.code("""
// Creating an object
const user = { name: "Alice" };

// Check if it has a toString method directly
console.log(user.hasOwnProperty("toString"));  // false

// But we can still call toString because it exists in Object.prototype
console.log(user.toString());  // "[object Object]"

// We can modify Object.prototype
Object.prototype.isAdmin = false;

// Now all objects have isAdmin property
console.log(user.isAdmin);  // false
        """, language="javascript")
    
    st.write("""
    ### How Prototype Pollution Happens
    
    Prototype pollution typically occurs when user-controlled input is used to recursively merge objects
    or set properties using paths, without proper validation. This allows an attacker to inject properties 
    like `__proto__` or modify existing prototype properties.
    """)
    
    st.code("""
// Vulnerable deep merge function
function merge(target, source) {
    for (let key in source) {
        if (key === "__proto__") {
            // DANGER: This allows prototype pollution!
            for (let protoKey in source[key]) {
                target[key][protoKey] = source[key][protoKey];
            }
        } else if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Attack payload
const malicious = JSON.parse('{"__proto__": {"isAdmin": true}}');
const config = {};

merge(config, malicious);

// Now ALL objects have isAdmin=true
console.log({}.isAdmin);  // true
    """, language="javascript")
    
    st.warning("""
    **Security Impact:**
    
    Prototype pollution can lead to:
    
    1. **Property Injection**: Adding unexpected properties to application objects
    2. **Denial of Service**: Causing application crashes by overriding critical properties
    3. **Remote Code Execution**: In some cases, modifying prototype methods used in security checks
    4. **Authentication Bypass**: Polluting properties used for access control decisions
    """)

elif lab_option == "Interactive Playground":
    st.header("Interactive Playground")
    
    st.write("""
    Explore how prototype pollution works with this interactive playground.
    You can modify the JSON input to see how it affects the application state.
    """)
    
    # JSON Input for Prototype Pollution
    st.subheader("Input JSON")
    
    default_json = """{
  "name": "User1",
  "preferences": {
    "theme": "dark"
  }
}"""
    
    malicious_examples = {
        "Basic Prototype Pollution": """{
  "__proto__": {
    "isAdmin": true
  },
  "name": "User1"
}""",
        "Nested Property Attack": """{
  "preferences": {
    "__proto__": {
      "canEdit": true
    }
  },
  "name": "User1"
}""",
        "Function Hijacking": """{
  "__proto__": {
    "toString": "function() { return 'Hijacked'; }"
  }
}"""
    }
    
    example_selection = st.selectbox(
        "Select an example payload",
        ["Custom Input"] + list(malicious_examples.keys())
    )
    
    if example_selection != "Custom Input":
        user_json = st.text_area("Edit JSON payload", malicious_examples[example_selection], height=200)
    else:
        user_json = st.text_area("Enter JSON payload", default_json, height=200)
    
    # Vulnerable Code
    st.subheader("Vulnerable Code")
    
    code_option = st.radio(
        "Select vulnerability pattern",
        ["Object Merging", "JSON Parsing", "Query String Parsing"]
    )
    
    if code_option == "Object Merging":
        st.code(VULNERABLE_MERGE_FUNCTION, language="javascript")
    elif code_option == "JSON Parsing":
        st.code(VULNERABLE_JSON_PARSE, language="javascript")
    else:
        st.code(VULNERABLE_QUERY_PARSER, language="javascript")
    
    # Simulate execution
    if st.button("Execute Code"):
        try:
            user_data = json.loads(user_json)
            
            # Check for potential prototype pollution
            has_proto = "__proto__" in user_data or any(
                isinstance(val, dict) and "__proto__" in val 
                for val in user_data.values() if isinstance(val, dict)
            )
            
            st.subheader("Execution Results")
            
            if has_proto:
                st.markdown("""
                <div class="vuln-box danger-box">
                <strong>⚠️ Prototype Pollution Detected!</strong><br/>
                The input contains __proto__ which can modify the prototype chain of objects.
                </div>
                """, unsafe_allow_html=True)
                
                # Show what would happen
                st.write("#### Impact Simulation")
                
                # Extract the polluted properties
                polluted_props = {}
                
                if "__proto__" in user_data:
                    for key, value in user_data["__proto__"].items():
                        polluted_props[key] = value
                
                # Also check nested objects
                for val in user_data.values():
                    if isinstance(val, dict) and "__proto__" in val:
                        for key, value in val["__proto__"].items():
                            polluted_props[key] = value
                
                # Show the polluted properties
                if polluted_props:
                    st.write("The following properties would be added to all objects:")
                    for key, value in polluted_props.items():
                        st.code(f"Object.prototype.{key} = {value};", language="javascript")
                    
                    st.write("This means:")
                    for key, value in polluted_props.items():
                        st.markdown(f"- All objects would now have a `{key}` property with value `{value}`")
                    
                    # Show potential impact
                    if "isAdmin" in polluted_props:
                        st.error("This could bypass authorization checks that rely on isAdmin property!")
                    if "toString" in polluted_props or "valueOf" in polluted_props:
                        st.error("This could cause application crashes by overriding core object methods!")
            else:
                st.markdown("""
                <div class="vuln-box success-box">
                <strong>✅ No immediate prototype pollution detected</strong><br/>
                The input doesn't contain explicit __proto__ properties.
                </div>
                """, unsafe_allow_html=True)
            
            # Show the parsed object
            st.write("#### Parsed Input")
            st.json(user_data)
            
        except json.JSONDecodeError:
            st.error("Invalid JSON. Please check your input.")

elif lab_option == "Real-world Examples":
    st.header("Real-world Prototype Pollution Examples")
    
    st.write("""
    Prototype pollution has affected many popular JavaScript libraries and applications.
    Here are some real-world examples of prototype pollution vulnerabilities:
    """)
    
    # Example 1: lodash
    display_vulnerability_scenario(
        title="lodash Vulnerability (CVE-2019-10744)",
        code_sample="""
// Vulnerable versions of lodash.merge
const _ = require('lodash');
const userInput = JSON.parse('{"__proto__": {"polluted": true}}');

// This is vulnerable to prototype pollution
_.merge({}, userInput);

// Now this is true for all objects
console.log({}.polluted);  // true
        """,
        description="""
        In 2019, a severe prototype pollution vulnerability was discovered in the popular utility library lodash.
        The `merge`, `mergeWith`, and other related functions were vulnerable to prototype pollution attacks.
        """,
        exploitation={
            "description": "An attacker could exploit this by sending a payload like:",
            "code": """
// Attacker's payload
fetch('/api/settings', {
    method: 'POST',
    body: JSON.stringify({
        "__proto__": {
            "isAdmin": true,
            "toString": "function() { alert('XSS'); }"
        }
    })
});
            """
        }
    )
    
    # Example 2: jQuery
    display_vulnerability_scenario(
        title="jQuery $.extend() Vulnerability",
        code_sample="""
// Vulnerable in some jQuery versions
const userOptions = JSON.parse('{"__proto__": {"isAdmin": true}}');

// This would pollute Object.prototype
$.extend(true, {}, userOptions);

// Now all objects have isAdmin=true
console.log({}.isAdmin);  // true
        """,
        description="""
        jQuery's `$.extend()` function, when used with deep extension (passing `true` as first parameter),
        was vulnerable to prototype pollution in some versions.
        """
    )
    
    # Example 3: Node.js applications
    display_vulnerability_scenario(
        title="Prototype Pollution in Express Applications",
        code_sample="""
// A common pattern in Express apps
function mergeParams(req, res, next) {
    // Combine query parameters and body
    req.allParams = {};
    const sources = [req.query, req.body];
    
    for (const source of sources) {
        for (const key in source) {
            if (typeof source[key] === 'object') {
                if (!req.allParams[key]) req.allParams[key] = {};
                deepMerge(req.allParams[key], source[key]);  // Vulnerable!
            } else {
                req.allParams[key] = source[key];
            }
        }
    }
    
    next();
}
        """,
        description="""
        Many Node.js applications use custom merging functions to combine parameters from different sources,
        which can lead to prototype pollution if user input is not properly sanitized.
        """,
        exploitation={
            "description": "An attacker could send a request like:",
            "code": """
// POST request with body:
{
  "__proto__": {
    "admin": true,
    "canEdit": true
  }
}

// Or a GET request with query string:
// ?__proto__[admin]=true&__proto__[canEdit]=true
            """
        }
    )
    
    st.subheader("Impact in Real Applications")
    
    st.write("""
    The impact of prototype pollution in real applications can be severe:
    
    1. **Server-Side Prototype Pollution**
       - Server crashes
       - Remote code execution in some cases
       - Authentication and authorization bypasses
    
    2. **Client-Side Prototype Pollution**
       - Cross-site scripting (XSS)
       - Client-side logic bypasses
       - DOM-based vulnerabilities
    """)

elif lab_option == "Prevention Techniques":
    st.header("Prevention Techniques")
    
    st.write("""
    Preventing prototype pollution requires careful handling of untrusted data,
    especially when merging objects or setting properties via user-controlled paths.
    """)
    
    # Technique 1
    st.subheader("1. Use Object.create(null)")
    
    st.write("""
    Create objects without a prototype chain using `Object.create(null)`.
    These "pure" objects can't be affected by prototype pollution.
    """)
    
    st.code("""
// Instead of:
const config = {};

// Use:
const config = Object.create(null);

// Now config has no prototype chain
console.log(config.__proto__);  // undefined
console.log(config.toString);   // undefined
    """, language="javascript")
    
    # Technique 2
    st.subheader("2. Check for __proto__ and constructor Properties")
    
    st.write("""
    Explicitly check for and reject dangerous property names like `__proto__` and `constructor`.
    """)
    
    st.code("""
function safeDeepMerge(target, source) {
    for (const key in source) {
        // Skip dangerous properties
        if (key === '__proto__' || key === 'constructor') {
            continue;
        }
        
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            safeDeepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
    """, language="javascript")
    
    # Technique 3
    st.subheader("3. Use Object.hasOwnProperty")
    
    st.write("""
    Always use `Object.hasOwnProperty.call(obj, prop)` to check if a property belongs to the object itself,
    not its prototype chain.
    """)
    
    st.code("""
function safeIteration(obj) {
    for (const key in obj) {
        // Only process own properties
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
            // It's safe to work with this property
            console.log(key, obj[key]);
        }
    }
}
    """, language="javascript")
    
    # Technique 4
    st.subheader("4. Use Safe Alternatives to Deep Merging")
    
    st.write("Here's a safer version of the merge function we saw earlier:")
    
    st.code(SAFE_MERGE_FUNCTION, language="javascript")
    
    # Technique 5
    st.subheader("5. JSON Schema Validation")
    
    st.write("""
    Validate user input against a schema before processing it.
    This ensures only expected properties are processed.
    """)
    
    st.code("""
const Ajv = require('ajv');
const ajv = new Ajv();

const schema = {
    type: 'object',
    properties: {
        name: { type: 'string' },
        preferences: {
            type: 'object',
            properties: {
                theme: { type: 'string' }
            },
            additionalProperties: false
        }
    },
    additionalProperties: false
};

function processUserInput(input) {
    const valid = ajv.validate(schema, input);
    
    if (!valid) {
        throw new Error('Invalid input');
    }
    
    // Now safe to use the input
    return input;
}
    """, language="javascript")
    
    # Technique 6
    st.subheader("6. Use Safe Libraries")
    
    st.write("""
    Use libraries that are designed to be safe against prototype pollution:
    
    - **lodash/fp** - Functional programming version of lodash
    - **Immutable.js** - Immutable data structures
    - **Object.freeze()** - To prevent modifications to objects
    """)
    
    st.code("""
// Using Object.freeze
const config = Object.freeze({
    isAdmin: false,
    permissions: Object.freeze({
        canEdit: false
    })
});

// This will fail in strict mode
try {
    config.isAdmin = true;  // Error in strict mode
} catch (e) {
    console.error("Cannot modify frozen object");
}
    """, language="javascript")
    
    # Technique 7
    st.subheader("7. Use JSON.parse with Reviver Function")
    
    st.write("When parsing JSON from untrusted sources, use a reviver function:")
    
    st.code(SAFE_JSON_PARSE, language="javascript")
    
    st.success("""
    **Best Practice Summary**
    
    1. Create objects with `Object.create(null)` when appropriate
    2. Explicitly check and reject `__proto__` and `constructor` properties
    3. Use `Object.hasOwnProperty.call()` when iterating over object properties
    4. Prefer immutable data structures
    5. Validate input with JSON Schema
    6. Keep dependencies updated
    7. Use JSON.parse with a reviver function
    """)

elif lab_option == "Challenge Lab":
    st.header("Prototype Pollution Challenge Lab")
    
    st.write("""
    Test your understanding of prototype pollution with these challenges.
    Try to identify the vulnerability and fix it in each case.
    """)
    
    # Challenge 1
    st.subheader("Challenge 1: Identify the Vulnerability")
    
    challenge1_code = """
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
"""

    st.code(challenge1_code, language="javascript")
    
    with st.expander("Hint"):
        st.write("""
        Look at the `recursiveMerge` function. It merges properties from source to target without any validation.
        What happens if the `userConfig` contains a `__proto__` property?
        """)
    
    show_solution1 = st.checkbox("Show Solution for Challenge 1")
    
    if show_solution1:
        st.write("""
        **Vulnerability**: The `recursiveMerge` function doesn't check for dangerous properties like `__proto__`.
        An attacker could send a payload like:
        """)
        
        st.code("""
const maliciousConfig = {
    "__proto__": {
        "features": {
            "advanced": true
        }
    }
};
        """, language="javascript")
        
        st.write("**Fix**:")
        
        st.code("""
function processConfig(defaultConfig, userConfig) {
    function safeMerge(target, source) {
        for (const key in source) {
            // Skip __proto__ and constructor
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
    }
    
    // Use Object.create(null) for a prototypeless object
    const finalConfig = Object.create(null);
    safeMerge(finalConfig, defaultConfig);
    safeMerge(finalConfig, userConfig);
    
    return finalConfig;
}
        """, language="javascript")
    
    # Challenge 2
    st.subheader("Challenge 2: Fix the Vulnerability")
    
    challenge2_code = """
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

// Example usage:
// parseQueryParams("https://example.com?user.name=John&user.role=admin")
// Should return: { user: { name: "John", role: "admin" } }
"""

    st.code(challenge2_code, language="javascript")
    
    your_solution = st.text_area("Write your solution here:", height=300)
    
    if st.button("Check Solution"):
        if your_solution:
            # Basic check for key security fixes
            checks = {
                "checks_proto": "__proto__" in your_solution.lower(),
                "hasOwnProperty": "hasownproperty" in your_solution.lower(),
                "object_create": "object.create" in your_solution.lower()
            }
            
            score = sum(checks.values()) / len(checks)
            
            st.write("### Solution Analysis")
            
            if score >= 0.5:
                st.success(f"Good job! Your solution includes some important security fixes.")
                
                # Highlight good practices found
                if checks["checks_proto"]:
                    st.write("✅ Checking for dangerous `__proto__` property")
                else:
                    st.write("❌ Consider checking for `__proto__` property")
                    
                if checks["hasOwnProperty"]:
                    st.write("✅ Using `hasOwnProperty` for safe property access")
                else:
                    st.write("❌ Consider using `Object.prototype.hasOwnProperty.call()`")
                    
                if checks["object_create"]:
                    st.write("✅ Using `Object.create(null)` for prototype-less objects")
            else:
                st.warning("Your solution might miss some important security fixes.")
                st.write("""
                Consider:
                1. Checking for `__proto__` and `constructor` properties
                2. Using `Object.prototype.hasOwnProperty.call()`
                3. Using `Object.create(null)` for prototype-less objects
                """)
            
            with st.expander("See a complete solution"):
                st.code("""
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

// Example usage:
// parseQueryParams("https://example.com?user.name=John&user.role=admin")
// Should return: { user: { name: "John", role: "admin" } }
                """, language="javascript")
            
            with st.expander("Explanation"):
                st.write("""
                The key security improvements in this solution:
                
                1. **Using Object.create(null)** - Creates an object with no prototype, so it's immune to prototype pollution
                2. **Skipping dangerous properties** - Explicitly checks for and ignores `__proto__` and `constructor` keys
                3. **Checking nested properties** - Also checks for dangerous properties in nested paths
                """)
        else:
            st.warning("Please write your solution before checking.")
    
    # Interactive Demo
    st.subheader("Interactive Prototype Pollution Demo")
    
    st.write("""
    This interactive demo shows how prototype pollution can affect application behavior.
    Enter different JSON inputs to see how they might pollute the Object prototype.
    """)
    
    demo_tabs = st.tabs(["Demo 1: Object Merging", "Demo 2: Query Parameter Parsing"])
    
    with demo_tabs[0]:
        st.write("""
        This demo shows how object merging can lead to prototype pollution.
        Try adding a `__proto__` property with various values.
        """)
        
        demo1_code = st.code("""
// Vulnerable merge function
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

const defaultConfig = { debug: false, logging: false };
const userConfig = /* Your JSON here */;

// Merge configs
merge({}, userConfig);

// Check if pollution succeeded
console.log({}.isAdmin);  // Should be undefined unless polluted
""", language="javascript")
        
        demo1_input = st.text_area(
            "Enter JSON for userConfig:",
            """{
  "__proto__": {
    "isAdmin": true
  }
}""",
            key="demo1_input"
        )
        
        if st.button("Run Demo 1"):
            try:
                user_json = json.loads(demo1_input)
                
                has_proto = "__proto__" in user_json
                polluted_props = {}
                
                if has_proto and isinstance(user_json["__proto__"], dict):
                    polluted_props = user_json["__proto__"]
                
                st.write("#### Execution Results")
                
                if has_proto:
                    st.markdown("""
                    <div class="vuln-box danger-box">
                    <strong>⚠️ Prototype Pollution Detected!</strong><br/>
                    The vulnerable merge function would allow properties to be added to Object.prototype.
                    </div>
                    """, unsafe_allow_html=True)
                    
                    st.write("After executing this code:")
                    
                    for key, value in polluted_props.items():
                        st.write(f"- `{{}}.{key}` would be: `{value}`")
                        
                    st.write("""
                    #### Impact
                    All objects in the application would now have these properties, potentially leading to:
                    """)
                    
                    if "isAdmin" in polluted_props:
                        st.write("- Authentication bypasses if code checks for `.isAdmin`")
                    if "toString" in polluted_props or "valueOf" in polluted_props:
                        st.write("- Application crashes by overriding core methods")
                    if any(k for k in polluted_props.keys() if k not in ["isAdmin", "toString", "valueOf"]):
                        st.write("- Unexpected behavior in application logic")
                else:
                    st.info("No prototype pollution detected in this input.")
            except json.JSONDecodeError:
                st.error("Invalid JSON. Please check your input.")
    
    with demo_tabs[1]:
        st.write("""
        This demo shows how parsing query parameters can lead to prototype pollution.
        Try crafting a malicious URL with query parameters.
        """)
        
        demo2_code = st.code("""
// Vulnerable query parser (simplified)
function parseQuery(queryString) {
    const params = {};
    const pairs = queryString.split('&');
    
    for (let i = 0; i < pairs.length; i++) {
        const [key, value] = pairs[i].split('=');
        
        // Vulnerable deep property setter
        setProperty(params, key, value);
    }
    
    return params;
}

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
""", language="javascript")
        
        demo2_input = st.text_input(
            "Enter malicious query string:",
            "__proto__.isAdmin=true&user.name=hacker",
            key="demo2_input"
        )
        
        if st.button("Run Demo 2"):
            parts = demo2_input.split("&")
            has_proto = any("__proto__" in p for p in parts)
            
            proto_params = {}
            normal_params = {}
            
            for part in parts:
                if "=" in part:
                    key, value = part.split("=", 1)
                    if key.startswith("__proto__"):
                        proto_path = key[len("__proto__."):]
                        if proto_path:
                            proto_params[proto_path] = value
                        else:
                            proto_params["direct"] = value
                    else:
                        normal_params[key] = value
            
            st.write("#### Query Parameter Analysis")
            
            if has_proto:
                st.markdown("""
                <div class="vuln-box danger-box">
                <strong>⚠️ Prototype Pollution Detected in Query!</strong><br/>
                The vulnerable query parser would allow properties to be added to Object.prototype.
                </div>
                """, unsafe_allow_html=True)
                
                st.write("Polluted prototype properties:")
                for key, value in proto_params.items():
                    if key == "direct":
                        st.code(f"Object.prototype = {value};", language="javascript")
                    else:
                        st.code(f"Object.prototype.{key} = '{value}';", language="javascript")
                
                st.write("Normal parameters:")
                for key, value in normal_params.items():
                    st.code(f"params['{key}'] = '{value}';", language="javascript")
                
                st.write("""
                #### Impact
                
                This type of attack is particularly dangerous in web applications because:
                
                1. Query parameters are often directly parsed from user input
                2. The attack can be executed just by visiting a crafted URL
                3. It may be possible to execute XSS attacks by polluting methods like toString
                """)
            else:
                st.info("No prototype pollution detected in this query string.")
    
    # Final Challenge
    st.subheader("Final Challenge: Real-world Application")
    
    st.write("""
    A Node.js application uses the following code to process user settings.
    Identify all vulnerabilities and provide a secure version of the code.
    """)
    
    final_challenge = """
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
"""
    
    st.code(final_challenge, language="javascript")
    
    final_solution = st.text_area("Your secure implementation:", height=400, key="final_solution")
    
    if st.button("Submit Final Solution"):
        if final_solution:
            # Check for key security patterns
            checks = {
                "object_create": "object.create(null)" in final_solution.lower(),
                "proto_check": "__proto__" in final_solution.lower() and "constructor" in final_solution.lower(),
                "hasownproperty": "hasownproperty" in final_solution.lower(),
                "deep_clone": "json.parse(json.stringify" in final_solution.lower() or "structuredclone" in final_solution.lower(),
                "freeze": "object.freeze" in final_solution.lower()
            }
            
            score = sum(checks.values()) / len(checks)
            
            st.write("### Solution Analysis")
            
            if score >= 0.6:
                st.success(f"Excellent job! You've implemented several important security protections.")
                
                # Specific feedback
                for check, result in checks.items():
                    if check == "object_create" and result:
                        st.write("✅ Using Object.create(null) for prototype-less objects")
                    elif check == "proto_check" and result:
                        st.write("✅ Checking for dangerous __proto__ and constructor properties")
                    elif check == "hasownproperty" and result:
                        st.write("✅ Using Object.prototype.hasOwnProperty for safe property access")
                    elif check == "deep_clone" and result:
                        st.write("✅ Creating deep clones of objects to prevent reference manipulation")
                    elif check == "freeze" and result:
                        st.write("✅ Using Object.freeze to prevent modifications")
            else:
                st.warning("Your solution might be missing some important security protections.")
                
                # Suggest improvements
                missing = []
                if not checks["object_create"]:
                    missing.append("Consider using Object.create(null) for prototype-less objects")
                if not checks["proto_check"]:
                    missing.append("Check for dangerous __proto__ and constructor properties")
                if not checks["hasownproperty"]:
                    missing.append("Use Object.prototype.hasOwnProperty for safe property access")
                if not checks["deep_clone"]:
                    missing.append("Create deep clones of objects to prevent reference manipulation")
                if not checks["freeze"]:
                    missing.append("Consider using Object.freeze to prevent modifications")
                
                for suggestion in missing:
                    st.write(f"❓ {suggestion}")
            
            with st.expander("See a comprehensive solution"):
                st.code("""
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
        
        // Check user access level
        if (updatedSettings.features.admin) {
            // Additional security check - validate admin status from auth service
            // This prevents relying solely on a property that could be polluted
            if (!isUserActuallyAdmin(req)) {
                return res.status(403).json({ error: "Unauthorized admin access attempt" });
            }
            
            res.json({ 
                message: "Admin settings applied",
                settings: updatedSettings
            });
        } else {
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

// Mock function for admin validation
function isUserActuallyAdmin(req) {
    // In a real app, this would validate the user's auth token
    // against a database or auth service
    return req.headers['x-admin-token'] === 'valid-admin-token';
}

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
                """, language="javascript")
                
                st.write("""
                **Key Security Improvements:**
                
                1. **Object.freeze** - Made the default settings immutable
                2. **Deep cloning** - Creates fresh copies to avoid reference manipulation
                3. **Safe update function** - Prevents prototype pollution by:
                   - Using Object.create(null) for prototypeless objects
                   - Explicitly checking for dangerous properties (__proto__, constructor, prototype)
                   - Using Object.prototype.hasOwnProperty.call()
                   - Recursively applying the same safeguards to nested objects
                4. **Additional authorization check** - Not relying solely on the potentially polluted property for security decisions
                5. **Safe filtering** - Creating a new object rather than modifying the existing one
                6. **Error handling** - Proper error handling and status codes
                """)
        else:
            st.warning("Please write your solution before submitting.")

# Add resources section at the bottom
st.sidebar.markdown("---")
st.sidebar.subheader("Additional Resources")
st.sidebar.markdown("""
* [OWASP Prototype Pollution Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)
* [HackTricks - Prototype Pollution](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution)
* [Snyk - Prototype Pollution Explained](https://snyk.io/blog/after-three-years-of-silence-a-new-jquery-prototype-pollution-vulnerability-emerges-once-again/)
* [PortSwigger Web Security Academy](https://portswigger.net/web-security)
""")

# Add disclaimer
st.sidebar.markdown("---")
st.sidebar.warning("""
**Educational Purpose Only**: This lab is intended for educational purposes to understand security vulnerabilities. Always practice ethical hacking and obtain proper authorization before testing any system.
""")
