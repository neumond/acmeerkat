# ACMEerkat: the ACME client

## Why another ACME client?

I want to build a fully customizable and programmable client with a clean API, rather than yet another ordinary CLI utility that optimizes a single happy path for delivering a certificate. Everything must be replaceable, including even the HTTP client. The core must be easy to audit and must consist only of simple, readable, structured code, rather than a thousand lines of compressed cryptographic magic.

It would not be written in Bash. Bash is hard to read and hard to write. The task is complex enough that using Python yields substantial benefits, yet it is not demanding enough to require compiled languages. While Bash is ubiquitous and installing a single-file script is a no-brainer, making it work correctly is hard. You always have to experiment to figure out things like the resulting file layout, and you cannot simply import the script and use its API to do the precise thing you need; it is always a complex command-line utility.

Storing all the data as regular files does not fit every setup. On Kubernetes, it could be better to avoid using volumes and instead store certificates and related data in native objects such as ConfigMaps and Secrets. Wildcard certificates could be shared with several remote machines. You may want to use different Let's Encrypt accounts for different certificates. The ways to install and apply a new certificate vary greatly depending on the environment (e.g., containers) and the HTTP server used, especially if you want to increase safety by dropping as many privileges as possible.

No hooks, no plugins — just plain old OOP and DI. Automate precisely what you want, and even if you don't know the details of the ACME protocol, the API will give you an intuitive feel for it.
