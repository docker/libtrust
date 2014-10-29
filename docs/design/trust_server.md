# The *libtrust* Trust Server

## What the Trust Server is

- a service to aid in the verification of signed content by providing proof of ownership of content to the signer.

- an extension of a local key chain to a larger key chain graph by providing the key chain links needed to verify signed content.

- a service which understands signed content to extract the information needed to link the signer to content.

- a service which queries a source data graph to prove ownership and signs the statement containing the proof using a private key which is part of an X509 chain rooted at the Docker CA.

- a simple interface to return signed statements of proof given signed content.

## What the Trust Server is NOT

- a datastore

- a CRUD service for key and ACL management

# Design

### Statement Queries

The Trust Server can be queried for statements by sending signed content.  The signed content must be a JSON Web Signature with the content type understood by the Trust Server.  The Trust Server will use the public key of the valid signature, identifier associated with the content, and action from the content  to query.  The action may be derived from the content (image manifest means builds) or explicitly stated such as a “scope” field in a JWT.  Requiring a valid signature ensures that queries cannot be made for public keys and identifiers which have no association.  This prevents potential abuse of the system by making it impossible to scrape the system for information which is not already public.  This also allows querying without additional authorization since having possession of the content grants access to the links to verify it.  

### Statement

The Trust Server returns a signed statement containing a list of relevant graph edges needed to traverse the graph for a given query.  The statement contains both a list of additive and revocation permissions.  Every statement has an expiration which is expected to be cached for repeat queries of the same content.  Revocations should be included for up to the expiration time to ensure any valid cached data may be overridden.  The signature on the statements should chain to the root Docker CA configured for the engine.

Example
~~~~
{
   "revocations": [
      {
         "subject": "/other",
         "scope": ["build"],
         "grantee": "LYRA:YAG2:QQKS:376F:QQXY:3UNK:SXH7:K6ES:Y5AU:XUN5:ZLVY:KBYL"
      }
   ],
   "grants": [
      {
         "subject": "/library",
         "scope": ["build"],
         "grantee": "LYRA:YAG2:QQKS:376F:QQXY:3UNK:SXH7:K6ES:Y5AU:XUN5:ZLVY:KBYL"
      }
   ],
   "expiration": "2014-12-29T00:08:20.565183779Z",
   "issuedAt": "2014-09-30T00:08:20.565183976Z",
   "signatures": [
      {
         "header": {
            "alg": "ES256",
            "x5c": [
               "MIIBnTCCA...",
               "MIIBnjC..."
            ]
         },
         "signature": "uYMwXO86...",
         "protected": "eyJmb3JtY..."
      }
   ]
}
~~~~

### Scopes
The scope used in grants and revocations are an array strings referring to verbs.  Grants can be chained together through delegation verbs.  When the subject ends with a “/” the scope applies to all child elements.

#### Example Scopes
build - scope used for verifying build manifests
connect - scope used for allowing connections to host or service

#### Reserved Scopes
any - Allows any scope except delegate
delegate - Allows delegation of any scope (implies “any” on entire subtree)
delegate_* - Allows delegation only on a specific scope (applies to entire subtree)

### Subject
The subject is the namespace in which the scope may be applied.  When chaining the subject must correspond to a grantee in the next link.  When the subject ends with a “/”, the scope is considered to be applicable only on children, not directly on the named subject.

### Grantee
The grantee is the namespace which is permitted to perform the scope verb on the subject.  The first grantee in a chain of grants will usually be a public key since a public key is easily authenticated through a signature.  The first grantee should always be authenticated by the service consuming the trust graph.

### API
The Trust Server can have one or multiple ways to make queries.  The socket must be over TLS to prevent MITM sniffing of sent content,   a false statement cannot be generated through MITM.

#### via REST
The Trust Server has a single endpoint which accepts contents via the request body and returns an array of statements via the response body.
POST /graph/`content-type`

#### via libchan
Request struct
~~~~
{
  "content": <byte array of content>
  "ret": <return statement channel>
}
~~~~

Return struct
~~~~
{
  "result": <int result code>
  "statements": <array of statement byte arrays>
}
~~~~

### Namespacing
Any given trust server may be responsible for the entire or subset of the namespace.  When receiving queries for sections of the namespace which are unowned, the trust server should be able to proxy requests other trust servers.  This means the trust server will need to be configured to know about other trust servers and which namespace those trust servers are responsible for.


### Top Level Namespaces
The top level namespace will not only be important for determining whether a x509 certificate has authority, but to categorize elements in the namespace.  For example keys and users have a specific relationship where users delegate to keys.  By proving ownership of a key, a delegation can give access to user.  However delegations should never go in the reverse direction, in which case a key delegates to a user, giving that user access to anyone who delegates to that key.  Since keys should never be the subject of a grant, no certificate should have authority over keys, meaning keys are in a separate top level namespace.  The keys top level namespace will be “/keys”, while users will be under a separate top level namespace such as “/object” or “/docker”.  The same could be true of emails which are granted authority through ownership of a DNS domain, not by the x509 certificate.

### Caching
Statements may be cached to disk and reloaded until the statement is expired.  After expiration the statement may still be used while offline, but once online should requery to get an updated statement which may account for any revocations.  The caching/requerying interval will balance security and performance.

### Chain of Trust
Statements returned by the trust server will be signed by a leaf certificate in an x509 chain.  All intermediate certificates will be listed in the “x5c” section of the JSON web signature to allow chaining to the root.  The libtrust client will need to have the x509 root certificate to verify statements.  Once a statement has been received  it may be cached or exported/imported since it will remain verifiable up until the statement expires.

### Backends
The trust server should have a pluggable interface to the graph data source.  The implementation of the graph queries is up to implementation of the interface.  The query to the backend is expected to be pre-authorized, no credentials will be provided to plugins.

### Backend Interface
The backend interface will be communicated over libchan using a job model and libchan objects as returned values.  Using libchan will allow the interface to be pluggable either in process or by a subprocess/container.

## Concerns
- Authentication is avoided by the trust server to allow anonymous querying to validate signed content.  This makes any signed content which does not contain an expiration forever vulnerable to replay by anyone in possession of the signed content .

- Leaking a “private” manifest allows making queries against the trust server which may expose a grant showing the user who build the image (if not part of the image name) and membership in the image name’s ownership group.  For example if a manifest for “privategroup/image1” was leaked and a query to the trust server returned grants for (secret user (delegate)-> key1, private group (build)-> secret user), then secret user’s identity and membership is leaked along with the manifest.  This can be mitigated by collapsing grants on the Trust Server, which is only possible if the returning trust server has authority over the subject which would get collapsed (may not be possible with proxying to multiple trust servers).

- Caching can keep revocations from getting picked up by clients.  The expiration time should be balanced to ensure that revocations take effect.  Revocations only need to be kept long enough to ensure that any previous statements concerning the subject have expired.


## Open Design Questions
- How should keys and other objects be separated at the top level namespace?

- Does the trust server proxy the content or create a new request (JWT) just for the subgraph that is needed?  In which case the trust server will need to verify the signature as part of the x509 chain and derive the public key from the content instead of signing key.  Would this just be a different content type or different endpoint?  Also once receiving statements, should the statements be passed on as is or combined.  Combining may not be possible if a trust server own only a subset and is not authorized to sign on the content it received.

- Do revocations need to stay around longer to act as limiters on permissive scopes (grant all to subtree except a specific element)?
