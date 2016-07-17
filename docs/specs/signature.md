# libtrust Signature

Libtrust uses JWS for signing content.  The JWS standard
is used unmodified. Libtrust adds protected headers which may
be used for additional formatting and meta data.  In addition to
JWS formatting, libtrust provides a legible JWS format which
maybe be converted to and from JWS without effecting the
signature.

## Example JWS
Shortened payload for display and therefore not verifiable
~~~~
{
   "payload": "ewogICAibmFlLFwiT3BlblN0ZGluXCI6ZmFsc2UsXCJTdGRpbk9uY2VcIjpmYWxzZSxcIkVudlwiOm51bGwsXCJDbWRcIjpudWxsLFwiRG5zXCI6bnVsbCxcIkltYWdlXCI6XCJcIixcIlZvbHVtZXNcIjpudWxsLFwiVm9sdW1lc0Zyb21cMFwiLFwiYXJjaGl0ZWN0dXJlXCI6XCJ4ODZfNjRcIn0iCiAgICAgIH0KICAgXSwKICAgInNjaGVtYVZlcnNpb24iOiAxCn0",
   "signatures": [
      {
         "header": {
            "jwk": {
               "crv": "P-256",
               "kid": "LYRA:YAG2:QQKS:376F:QQXY:3UNK:SXH7:K6ES:Y5AU:XUN5:ZLVY:KBYL",
               "kty": "EC",
               "x": "Cu_UyxwLgHzE9rvlYSmvVdqYCXY42E9eNhBb0xNv0SQ",
               "y": "zUsjWJkeKQ5tv7S-hl1Tg71cd-CqnrtiiLxSi6N_yc8"
            },
            "alg": "ES256",
            "cty": ""
         },
         "signature": "sgbJD2AJ-2Lu6KpbthnUyB6vSr9uVUAV9Cx8QtfA-0GwYR1U2XPivtA_FYDsWzTtvMTc25lZuaVdhgLLhOF65g",
         "protected": "eyJmb3JtYXRMZW5ndGgiOjEzMDM4LCJmb3JtYXRUYWlsIjoiQ24wIiwidGltZSI6IjIwMTQtMTEtMTRUMDc6NTc6MThaIn0"
      }
   ]
}

~~~~

## Protected Headers
- **time** - RFC3339 string
- **formatLength** - integer value representing the number of bytes
from the start of the sign content to (and including) the last non-whitespace
character before the closing '}' of the top level JSON object.  If the
content is not a JSON object or pretty format will not be supported, it
may  be omitted.
- **formatTail** - Signed content remaining after the formatLength.
The original signed content should be recreateable by taking the
original signed content up to the formatLength and appending this
value.  This may also be omitted if not a JSON object or not
supporting pretty format.

## Pretty format
A special format of the JWS for libtrust when the signed content is
a JSON object.  The pretty format is designed to be able to display
the content in a legible fashion while remaining convertible (and
by extension verifiable) back to JWS.  By default a JWS stores
the payload content as a base64 encoded value, which allows for
whitespace to be ignored.  In the pretty format, whitespace
cannot change and still remain verifiable.  If whitespace changes
cannot be avoided, then the Pretty format should not be used.

**NOTE** Since the format information is stored in protected
headers, it is included in the signature.  This ensure that the
content cannot be altered by simply changing the format
information.  However this means when conversion needs to
happen, the protected headers will need to be calculated
before adding the signature, even when the target output is
a JWS. The rules for calculating the tail and length may be
applied to an existing signature, but conversion back to JWS
may fail if the original content contained extra whitespace
or was poorly formatted JSON.

### Example Pretty
Modified for display and therefore not verifiable.
Verifiable version [here](https://registry-1.docker.io/v2/manifest/library/ubuntu/latest)
~~~~
{
   "name": "library/ubuntu",
   "tag": "latest",
   "architecture": "amd64",
   "fsLayers": [
      {
         "blobSum": "tarsum.dev+sha256:1b755912c77197c6a43539f2a708ef89d5849b8ce02642cb702e47afaa8195c3"
      },
      {
         "blobSum": "tarsum.dev+sha256:caa43099fdaad204486de00d6ed824506ee9bf3b8009b6f72110beae97b949a8"
      },
      {
         "blobSum": "tarsum.dev+sha256:db1824574c4475ef788e755ad9ea7b07795e040c69e0fb08078bcf8a745c0863"
      },
      {
         "blobSum": "tarsum.dev+sha256:acc405699365b1f562c5d3204bbdc9ed6b7adda5f91bd26269a3e0dd8434b538"
      },
      {
         "blobSum": "tarsum.dev+sha256:2f465e09b4115d37aa01da89f1d7f1041cea70920d299d6f28384f156e2433a1"
      },
      {
         "blobSum": "tarsum.dev+sha256:6068ecbe28714c762975ccaa2b6ef5204cb365f930bdb5a444e1902ebe965701"
      },
      {
         "blobSum": "tarsum.dev+sha256:324d4cf44ee7daa46266c1df830c61a7df615c0632176a339e7310e34723d67a"
      }
   ],
   "history": [
      {
         "v1Compatibility": "..."
      },
      {
         "v1Compatibility": "..."
      },
      {
         "v1Compatibility": "..."
      },
      {
         "v1Compatibility": "..."
      },
      {
         "v1Compatibility": "..."
      },
      {
         "v1Compatibility": "..."
      },
      {
         "v1Compatibility": "..."
      }
   ],
   "schemaVersion": 1,
   "signatures": [
      {
         "header": {
            "jwk": {
               "crv": "P-256",
               "kid": "LYRA:YAG2:QQKS:376F:QQXY:3UNK:SXH7:K6ES:Y5AU:XUN5:ZLVY:KBYL",
               "kty": "EC",
               "x": "Cu_UyxwLgHzE9rvlYSmvVdqYCXY42E9eNhBb0xNv0SQ",
               "y": "zUsjWJkeKQ5tv7S-hl1Tg71cd-CqnrtiiLxSi6N_yc8"
            },
            "alg": "ES256"
         },
         "signature": "sgbJD2AJ-2Lu6KpbthnUyB6vSr9uVUAV9Cx8QtfA-0GwYR1U2XPivtA_FYDsWzTtvMTc25lZuaVdhgLLhOF65g",
         "protected": "eyJmb3JtYXRMZW5ndGgiOjEzMDM4LCJmb3JtYXRUYWlsIjoiQ24wIiwidGltZSI6IjIwMTQtMTEtMTRUMDc6NTc6MThaIn0"
      }
   ]
}
~~~~

### Conversion from JWS
- Parse into hash array
- Decode "payload" key
- Extract format length from protected header (or calculate if missing)
- Create json block with signatures
- Concatenate payload up to format length + signatures block excluding open '{'

### Conversion to JWS
- Parse into hash array
- Check each signature section in "signature"
- Decode protected header, extract formatLength and formatTail
- If no formatLength or formatTail is given, calculate by finding the end of the last value
before the signature key, set formatTail to newline + '}'
- Create payload from original content up to the format length + the decoded formatTail
