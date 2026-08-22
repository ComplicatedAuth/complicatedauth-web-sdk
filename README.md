# `@complicatedauth/browser`

Framework-neutral browser client for a customer-owned ComplicatedAuth BFF. Project service credentials never enter the browser.

```ts
import {ComplicatedAuthClient} from "@complicatedauth/browser";

const auth = new ComplicatedAuthClient({baseUrl: "/auth"});
await auth.startLogin("person@example.com");
await auth.startPasswordAuth("correct horse battery staple");
const session = await auth.startPasskeyAuth();
```

For a newly provisioned user with no FIDO credential, replace the final call
with `startFirstPasskeyEnrollment()`. It is accepted only after password
verification and only while the user has no FIDO credentials; successful
registration completes the login.

Passkey, hybrid, and security-key authentication require a password factor in the same login attempt. Security-key credentials additionally require user verification and attestation. The BFF protocol is implemented by `@complicatedauth/server`.
