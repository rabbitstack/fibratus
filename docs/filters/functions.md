# Functions

Functions expand the scope of the filtering language by bringing a plethora of capabilities. The function can return a primitive value, including integers, strings, and booleans. Additionally, some functions may return a collection of values. Function names are case insensitive.

### Network functions

#### cidr_contains

`cidr_contains` determines if the specified IP is contained within the block referenced by the given CIDR mask. The first argument represents the IP address and the subsequent   arguments are IP masks in CIDR notation.

- **Specification**
    ```
    cidr_contains(ip: <string>, cidrs: <string>...) :: <boolean>
    ```
    - `ip`: The IP address in v4/v6 notation
    - `cidrs`: The list of CIDR masks
    - `return` a boolean value indicating whether the IP pertains to the CIDR block

- **Examples**

    Assuming the `net.sip` contains the `192.168.1.20` IP address, the following filter
    would match on this event.

    ```
    fibratus run kevt.category = 'net' and cidr_contains(net.sip, '192.168.1.1/24', '172.17.1.1/8')
    ```

### Hash functions

#### md5

`md5` computes the MD5 hash of the given value.

- **Specification**
    ```
    md5(data: <string|[]byte>) :: <string>
    ```
    - `data`: The string or the byte array for which to calculate the hash
    - `return` a string representing the md5 hash

- **Examples**

    Assuming the `registry.key.name` contains `HKEY_LOCAL_MACHINE\SYSTEM\Setup\Pid`, the following would filter events for the matching md5 hash.

    ```
    fibratus run kevt.category = 'net' and md5(registry.key.name) = 'eab870b2a516206575d2ffa2b98d8af5'
    ```