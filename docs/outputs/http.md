# HTTP

Sends events to local/remote endpoints via HTTP protocol. Requests are serialized to the data format specified by the `serializer` property, which by default encodes events as `JSON` payloads.

### Configuration {docsify-ignore}

The HTTP output configuration is located in the `outputs.http` section.

#### enabled

Indicates whether the HTTP output is enabled.

**default**: `false`

#### endpoints

Specifies a list of endpoints to which the events are forwarded. Each of the endpoints must contain the HTTP protocol scheme, that can be `http` or `https`.

#### timeout

Represents the timeout for the HTTP requests.

**default**: `5s`

#### proxy-url

Specifies the HTTP proxy URL. It overrides the HTTP proxy URL as indicated by the environment variables.

#### proxy-username

The username for HTTP proxy authentication.

#### proxy-password

The password for HTTP proxy authentication.

#### method

Determines the HTTP verb to use in requests.

**default**: `POST`

#### serializer

Specifies the event serializer type.

**default**: `json`

#### username

Username for the basic HTTP authentication.
   
#### password

Password for the basic HTTP authentication.

#### enable-gzip

If enabled, the HTTP body is compressed with the `gzip` compression.

**default**: `false`

#### headers

Represents a list of arbitrary headers to include in HTTP requests.

#### tls-key

Path to the public/private key file.

#### tls-cert

Path to the certificate file.

#### tls-ca

Represents the path of the certificate file that is associated with the Certification Authority (CA).

#### tls-insecure-skip-verify

Indicates if the chain and host verification stage is skipped.

**default**: `false`
