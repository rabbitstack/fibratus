# Object manager events

#### CreateSymbolicLinkObject

`CreateSymbolicLinkObject` event is fired when the symbolic link within the object manager directory. This event has the following parameters:

- `source` identifies the parameter that represents the source symbolic link object or other kernel object.
- `target` identifies the parameter that represents the target symbolic link object or other kernel object.
- `desired_access` denotes the access rights for the target symbolic link object. Can be the combination of `DELETE`, `READ_CONTROL`, `WRITE_DAC`, `WRITE_OWNER`, `SYNCHRONIZE`, `STANDARD_RIGHTS_REQUIRED`, `STANDARD_RIGHTS_ALL`, `ACCESS_SYSTEM_SECURITY`, `MAXIMUM_ALLOWED`, `GENERIC_READ`, `GENERIC_WRITE`, `GENERIC_EXECUTE`, `GENERIC_ALL`.
- `status` represents the outcome of the operation.