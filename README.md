# Express middleware for JWT verification


Written on Typescript and can be used only in a Typescript project at the moment.

## Usage 

```javascript
const jwksVerifyMiddleware = require('jwks-verify');
...
(create an Express app)
...
app.use(jwksVerifyMiddleware(
  {
    issuer: "token issuer host" // ex.  https://auth.example.com
  }
));
```
