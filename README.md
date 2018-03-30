# Express middleware for JWT verification

## Usage 

```javascript
const jwksVerifyMiddleware = require('jwks-verify');
...
(create an Express app)
...
app.use(jwksVerifyMiddleware(
  {
    issuer: "token issuer host, ex. https://auth.example.com"
  }
));
```
